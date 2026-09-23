// SPDX-FileCopyrightText: 2024-2026 Cloudflare Inc., Luke Curley, Mike English and contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Pure-Rust HTTPS fingerprint server: axum + tokio-rustls.
// (hyper-serve does not build against the workspace hyper-util resolution;
//  rustls feature-pinning alone is not enough to keep it.)

use std::{net, path::PathBuf, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_http::cors::{Any, CorsLayer};

pub struct WebConfig {
    pub bind: net::SocketAddr,
    pub tls: moq_native_ietf::tls::Config,
    pub qlog_dir: Option<PathBuf>,
    pub mlog_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct WebState {
    fingerprint: String,
    qlog_dir: Option<Arc<PathBuf>>,
    mlog_dir: Option<Arc<PathBuf>>,
}

/// HTTP(S) helper that serves `/fingerprint` (and optional qlog/mlog) for browsers.
pub struct Web {
    app: Router,
    bind: net::SocketAddr,
    tls: Arc<rustls::ServerConfig>,
}

impl Web {
    pub fn new(config: WebConfig) -> Self {
        let fingerprint = config
            .tls
            .fingerprints
            .first()
            .expect("missing certificate")
            .clone();

        let mut tls = config.tls.server.expect("missing server configuration");
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let state = WebState {
            fingerprint,
            qlog_dir: config.qlog_dir.map(Arc::new),
            mlog_dir: config.mlog_dir.map(Arc::new),
        };

        let mut app = Router::new().route("/fingerprint", get(serve_fingerprint));

        if state.qlog_dir.is_some() {
            app = app.route("/qlog/:cid", get(serve_qlog));
            tracing::info!("qlog files available at /qlog/:cid");
        }

        if state.mlog_dir.is_some() {
            app = app.route("/mlog/:cid", get(serve_mlog));
            tracing::info!("mlog files available at /mlog/:cid");
        }

        let app = app.with_state(state).layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET]),
        );

        Self {
            app,
            bind: config.bind,
            tls: Arc::new(tls),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.bind).await?;
        let acceptor = TlsAcceptor::from(self.tls);
        let app = self.app;

        tracing::info!("HTTPS fingerprint server listening on {}", self.bind);

        loop {
            let (tcp, remote_addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let tower_service = app.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(%remote_addr, error = %e, "TLS accept failed");
                        return;
                    }
                };

                let io = TokioIo::new(tls_stream);
                let hyper_service =
                    TowerToHyperService::new(tower_service.into_service());

                if let Err(err) = HyperConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, hyper_service)
                    .await
                {
                    tracing::debug!(%remote_addr, error = %err, "HTTPS connection error");
                }
            });
        }
    }
}

async fn serve_fingerprint(State(state): State<WebState>) -> impl IntoResponse {
    state.fingerprint
}

async fn serve_qlog(
    Path(cid): Path<String>,
    State(state): State<WebState>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let qlog_dir = state.qlog_dir.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "Qlog serving not enabled".to_string(),
    ))?;

    let base_cid = cid.strip_suffix("_server.qlog").unwrap_or(&cid);
    let filename = format!("{}_server.qlog", base_cid);
    let file_path = qlog_dir.join(&filename);

    let canonical_dir = qlog_dir.canonicalize().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid qlog directory: {}", e),
        )
    })?;

    let canonical_file = file_path.canonicalize().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("Qlog file not found: {}", filename),
        )
    })?;

    if !canonical_file.starts_with(&canonical_dir) {
        return Err((StatusCode::FORBIDDEN, "Invalid path".to_string()));
    }

    tokio::fs::read(&canonical_file).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("Failed to read qlog file: {}", e),
        )
    })
}

async fn serve_mlog(
    Path(cid): Path<String>,
    State(state): State<WebState>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let mlog_dir = state.mlog_dir.as_ref().ok_or((
        StatusCode::NOT_FOUND,
        "Mlog serving not enabled".to_string(),
    ))?;

    let base_cid = cid.strip_suffix("_server.mlog").unwrap_or(&cid);
    let filename = format!("{}_server.mlog", base_cid);
    let file_path = mlog_dir.join(&filename);

    let canonical_dir = mlog_dir.canonicalize().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid mlog directory: {}", e),
        )
    })?;

    let canonical_file = file_path.canonicalize().map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("Mlog file not found: {}", filename),
        )
    })?;

    if !canonical_file.starts_with(&canonical_dir) {
        return Err((StatusCode::FORBIDDEN, "Invalid path".to_string()));
    }

    tokio::fs::read(&canonical_file).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("Failed to read mlog file: {}", e),
        )
    })
}
