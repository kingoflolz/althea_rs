use althea_types::{Identity, LocalIdentity, PaymentTx};

use actix::registry::SystemService;
use actix_web::*;

use futures::Future;

use settings::RitaCommonSettings;
use SETTING;

use rita_common;
use rita_common::payment_controller::PaymentController;
use rita_common::tunnel_manager::{GetWgInterface, OpenTunnelListener, TunnelManager};

use std::boxed::Box;

#[derive(Serialize)]
pub struct JsonStatusResponse {
    response: String,
}

impl JsonStatusResponse {
    pub fn new(ret_val: Result<String, Error>) -> Result<Json<JsonStatusResponse>, Error> {
        let res_string = match ret_val {
            Ok(msg) => msg.clone(),
            Err(e) => format!("{}", e),
        };

        Ok(Json(JsonStatusResponse {
            response: res_string,
        }))
    }
}

pub fn make_payments(
    pmt: Json<PaymentTx>,
    req: HttpRequest,
) -> Box<Future<Item = HttpResponse, Error = Error>> {
    info!("Got Payment from {:?}", req.connection_info().remote());
    trace!("Received payment: {:?}", pmt,);
    PaymentController::from_registry()
        .send(rita_common::payment_controller::PaymentReceived(
            pmt.into_inner(),
        ))
        .from_err()
        .and_then(|_| Ok(HttpResponse::Ok().into()))
        .responder()
}

pub fn hello_response(
    their_id: Json<serde_json::Value>,
    req: HttpRequest,
) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    let new_id: Result<Identity, serde_json::Error> = serde_json::from_value(their_id.clone());
    let old_id: Result<LocalIdentity, serde_json::Error> = serde_json::from_value(their_id.clone());

    match new_id {
        Ok(new_id) => {
            info!("sending to new hello handler");
            hello_response_new(new_id, req)
        }
        Err(_) => match old_id {
            Ok(old_id) => {
                info!("sending to old hello handler");
                hello_response_old(old_id, req)
            }
            _ => panic!("did not match either"),
        },
    }
}

pub fn hello_response_new(
    their_id: Identity,
    req: HttpRequest,
) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    info!("Got Hello from {:?}", req.connection_info().remote());

    trace!("Received neighbour identity: {:?}", their_id);

    TunnelManager::from_registry()
        .send(OpenTunnelListener(their_id.clone()))
        .from_err()
        .and_then(move |_| {
            info!("opening tunnel in hello_response for {:?}", their_id);
            TunnelManager::from_registry()
                .send(GetWgInterface(their_id.mesh_ip))
                .from_err()
                .and_then(|wg_iface| {
                    Ok(Json(LocalIdentity {
                        global: SETTING.get_identity(),
                        wg_port: wg_iface?.listen_port,
                    }))
                })
        })
        .responder()
}

// TODO: REMOVE IN ALPHA 6
pub fn hello_response_old(
    their_id: LocalIdentity,
    req: HttpRequest,
) -> Box<Future<Item = Json<LocalIdentity>, Error = Error>> {
    info!("Got Hello from {:?}", req.connection_info().remote());

    trace!("Received neighbour identity: {:?}", their_id);

    TunnelManager::from_registry()
        .send(OpenTunnelListener(their_id.clone().global))
        .from_err()
        .and_then(move |_| {
            info!("opening tunnel in hello_response for {:?}", their_id);
            TunnelManager::from_registry()
                .send(GetWgInterface(their_id.global.mesh_ip))
                .from_err()
                .and_then(|wg_iface| {
                    Ok(Json(LocalIdentity {
                        global: SETTING.get_identity(),
                        wg_port: wg_iface?.listen_port,
                    }))
                })
        })
        .responder()
}

pub fn version(_req: HttpRequest) -> String {
    format!(
        "crate ver {}\ngit hash {}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    )
}
