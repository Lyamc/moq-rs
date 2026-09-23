// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use moq_transport::serve::{
    Datagram, DatagramsReader, DatagramsWriter, StreamReader, Subgroup, SubgroupWriter,
    SubgroupsReader, SubgroupsWriter, TrackReader, TrackReaderMode,
};

use tokio::task;

/// Publishes the current time every second in the format "YYYY-MM-DD HH:MM:SS"
pub struct Publisher {
    track_subgroups_writer: Option<SubgroupsWriter>,
    track_datagrams_writer: Option<DatagramsWriter>,
}

impl Publisher {
    pub fn new(track_subgroups_writer: SubgroupsWriter) -> Self {
        Self {
            track_subgroups_writer: Some(track_subgroups_writer),
            track_datagrams_writer: None,
        }
    }

    pub fn new_datagram(track_datagrams_writer: DatagramsWriter) -> Self {
        Self {
            track_subgroups_writer: None,
            track_datagrams_writer: Some(track_datagrams_writer),
        }
    }

    /// Runs the publisher, sending the current time every second.  Creates a new group for each minute.
    pub async fn run(mut self) -> anyhow::Result<()> {
        let start = UtcClock::now();
        let mut now = start;

        // Just for fun, don't start at zero.
        let mut next_group_id = start.minute();

        // Create a new group for each minute.
        loop {
            let next;
            if let Some(track_subgroups_writer) = &mut self.track_subgroups_writer {
                let subgroup_writer = track_subgroups_writer
                    .create(Subgroup {
                        group_id: next_group_id as u64,
                        subgroup_id: 0,
                        priority: 0,
                    })
                    .context("failed to create minute segment")?;

                // Spawn a new task to handle sending the object every second
                tokio::spawn(async move {
                    if let Err(err) = Self::send_subgroup_objects(subgroup_writer, now).await {
                        tracing::warn!("failed to send minute: {:?}", err);
                    }
                });

                next = now.next_minute_boundary();
            } else if let Some(track_datagrams_writer) = &mut self.track_datagrams_writer {
                let time_str = now.format_full();
                track_datagrams_writer
                    .write(Datagram {
                        group_id: next_group_id as u64,
                        object_id: 0,
                        priority: 127,
                        payload: time_str.clone().into_bytes().into(),
                        extension_headers: Default::default(),
                    })
                    .context("failed to write datagram")?;

                println!("{}", time_str);

                next = now.next_second_boundary();
            } else {
                return Err(anyhow::anyhow!("no track writer available"));
            }

            next_group_id += 1;

            // Sleep until the start of the next minute (stream mode) or next second (datagram mode)
            let delay = next.saturating_duration_since(now);
            tokio::time::sleep(delay).await;

            now = next; // just assume we didn't undersleep
        }
    }

    /// Sends the current time every second within a minute group.
    async fn send_subgroup_objects(
        mut subgroup_writer: SubgroupWriter,
        mut now: UtcClock,
    ) -> anyhow::Result<()> {
        // Everything but the second.
        let base = now.format_minute_prefix();

        subgroup_writer
            .write(base.clone().into())
            .context("failed to write base")?;

        loop {
            let delta = now.format_second();
            subgroup_writer
                .write(delta.clone().into())
                .context("failed to write delta")?;

            println!("{base}{delta}");

            let next = now.next_second_boundary();

            // Sleep until the next second
            let delay = next.saturating_duration_since(now);
            tokio::time::sleep(delay).await;

            // Get the current time again to check if we overslept
            let next = UtcClock::now();
            if next.minute() != now.minute() {
                return Ok(());
            }

            now = next;
        }
    }
}

/// Subscribes to the clock and prints received time updates to stdout.
pub struct Subscriber {
    track_reader: TrackReader,
}

impl Subscriber {
    pub fn new(track_reader: TrackReader) -> Self {
        Self { track_reader }
    }

    /// Runs the subscriber, receiving time updates and printing them to stdout.
    pub async fn run(self) -> anyhow::Result<()> {
        match self
            .track_reader
            .mode()
            .await
            .context("failed to get mode")?
        {
            TrackReaderMode::Stream(stream) => Self::recv_stream(stream).await,
            TrackReaderMode::Subgroups(subgroups) => Self::recv_subgroups(subgroups).await,
            TrackReaderMode::Datagrams(datagrams) => Self::recv_datagrams(datagrams).await,
        }
    }

    /// Receives time updates from a stream and prints them to stdout.
    async fn recv_stream(mut stream_reader: StreamReader) -> anyhow::Result<()> {
        while let Some(mut stream_group_reader) = stream_reader.next().await? {
            while let Some(object) = stream_group_reader.read_next().await? {
                let str = String::from_utf8_lossy(&object);
                println!("{str}");
            }
        }

        Ok(())
    }

    /// Receives time updates from subgroups and prints them to stdout.
    async fn recv_subgroups(mut subgroups_reader: SubgroupsReader) -> anyhow::Result<()> {
        while let Some(mut subgroup_reader) = subgroups_reader.next().await? {
            // Spawn a new task to handle the subgroup concurrently, so we
            // don't rely on the publisher ending the previous stream before starting a new one.
            task::spawn(async move {
                if let Err(e) = async {
                    let base = subgroup_reader
                        .read_next()
                        .await
                        .context("failed to get first object")?
                        .context("empty subgroup")?;

                    let base = String::from_utf8_lossy(&base);

                    while let Some(object) = subgroup_reader.read_next().await? {
                        let str = String::from_utf8_lossy(&object);
                        println!("{base}{str}");
                    }

                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    eprintln!("Error handling subgroup: {:?}", e);
                }
            });
        }

        Ok(())
    }

    /// Receives time updates from datagrams and prints them to stdout.
    async fn recv_datagrams(mut datagrams_reader: DatagramsReader) -> anyhow::Result<()> {
        while let Some(datagram) = datagrams_reader.read().await? {
            let str = String::from_utf8_lossy(&datagram.payload);
            println!("{str}");
        }

        Ok(())
    }
}

/// UTC clock based on `SystemTime`. Avoids `chrono`, whose timezone lookup
/// pulls `cc` on Haiku through `iana-time-zone`.
#[derive(Clone, Copy)]
struct UtcClock {
    /// Nanoseconds since the Unix epoch.
    nanos: u128,
}

impl UtcClock {
    fn now() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self { nanos }
    }

    fn unix_secs(&self) -> i64 {
        (self.nanos / 1_000_000_000) as i64
    }

    fn minute(&self) -> u32 {
        let tod = self.unix_secs().rem_euclid(86400) as u32;
        (tod % 3600) / 60
    }

    fn next_second_boundary(&self) -> Self {
        let sec = self.nanos / 1_000_000_000;
        Self {
            nanos: (sec + 1) * 1_000_000_000,
        }
    }

    fn next_minute_boundary(&self) -> Self {
        let sec = self.unix_secs();
        let minute_start = sec - sec.rem_euclid(60);
        Self {
            nanos: (minute_start as u128 + 60) * 1_000_000_000,
        }
    }

    fn saturating_duration_since(&self, earlier: Self) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos).min(u64::MAX as u128) as u64)
    }

    fn format_full(&self) -> String {
        let (y, m, d, h, min, s) = civil_from_unix(self.unix_secs());
        format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
    }

    fn format_minute_prefix(&self) -> String {
        let (y, m, d, h, min, _) = civil_from_unix(self.unix_secs());
        format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:")
    }

    fn format_second(&self) -> String {
        let (_, _, _, _, _, s) = civil_from_unix(self.unix_secs());
        format!("{s:02}")
    }
}

/// Howard Hinnant's `civil_from_days`. `unix_secs` is seconds since 1970-01-01 UTC.
fn civil_from_unix(unix_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let tod = unix_secs.rem_euclid(86_400) as u32;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32, hour, min, sec)
}

#[cfg(test)]
mod utc_clock_tests {
    use super::civil_from_unix;

    #[test]
    fn unix_epoch_and_known_instants() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_000_000_000), (2001, 9, 9, 1, 46, 40));
        assert_eq!(civil_from_unix(1_700_000_000), (2023, 11, 14, 22, 13, 20));
    }
}
