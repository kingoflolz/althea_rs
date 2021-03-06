use std::time::{Duration, Instant};

use actix::prelude::*;
use actix::registry::SystemService;

use rita_common::tunnel_manager::{GetNeighbors, TunnelManager};

use rita_common::traffic_watcher::{TrafficWatcher, Watch};

use rita_common::debt_keeper::{DebtKeeper, SendUpdate};

use rita_common::payment_controller::{PaymentController, PaymentControllerUpdate};

use rita_common::stats_collector::StatsCollector;

use failure::Error;
use rita_common::tunnel_manager::OpenTunnel;

use settings::RitaCommonSettings;
use SETTING;

pub struct RitaLoop {
    stats_collector: Addr<Syn, StatsCollector>,
}

impl RitaLoop {
    pub fn new() -> RitaLoop {
        RitaLoop {
            stats_collector: SyncArbiter::start(1, || StatsCollector::new()),
        }
    }
}

impl Actor for RitaLoop {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        ctx.run_later(Duration::from_secs(5), |_act, ctx| {
            let addr: Addr<Unsync, Self> = ctx.address();
            addr.do_send(Tick);
        });
    }
}

pub struct Tick;

impl Message for Tick {
    type Result = Result<(), Error>;
}

impl Handler<Tick> for RitaLoop {
    type Result = Result<(), Error>;
    fn handle(&mut self, _: Tick, ctx: &mut Context<Self>) -> Self::Result {
        trace!("Common tick!");

        // let mut babel = Babel::new(&format!("[::1]:{}", SETTING.get_network().babel_port).parse().unwrap());

        self.stats_collector.do_send(Tick {});

        let start = Instant::now();
        ctx.spawn(
            TunnelManager::from_registry()
                .send(GetNeighbors)
                .into_actor(self)
                .then(move |res, act, _ctx| {
                    let res = res.unwrap().unwrap();

                    info!("got neighbors: {:?}", res);

                    let neigh = Instant::now();

                    for &(ref their_id, _, ref ip) in &res {
                        TunnelManager::from_registry()
                            .do_send(OpenTunnel(their_id.clone(), ip.clone()));
                    }

                    let res = res
                        .iter()
                        .map(|input| (input.0.clone(), input.1.clone()))
                        .collect();

                    TrafficWatcher::from_registry()
                        .send(Watch(res))
                        .into_actor(act)
                        .then(move |_res, _act, ctx| {
                            info!("loop completed in {:?}", start.elapsed());
                            info!("traffic watcher completed in {:?}", neigh.elapsed());
                            DebtKeeper::from_registry().do_send(SendUpdate {});
                            PaymentController::from_registry().do_send(PaymentControllerUpdate {});
                            ctx.notify_later(
                                Tick {},
                                Duration::from_secs(SETTING.get_network().rita_tick_interval),
                            );
                            actix::fut::ok(())
                        })
                }),
        );
        Ok(())
    }
}
