//! Unmodified crates.io OPAQUE 3 server, isolated from the production dependency graph.
use opaque_ke::{
    CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}
fn send(value: Value) {
    println!("{value}");
    io::stdout().flush().unwrap();
}
fn main() {
    let setup = ServerSetup::<Suite>::new(&mut OsRng);
    let identity = b"synthetic-account";
    let mut record = None;
    let mut login = None;
    for line in io::stdin().lock().lines() {
        let message: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let bytes = hex::decode(message["bytes"].as_str().unwrap()).unwrap();
        match message["op"].as_str().unwrap() {
            "enroll-v3" => {
                let start = ClientRegistration::<Suite>::start(&mut OsRng, &bytes).unwrap();
                let response = ServerRegistration::start(&setup, start.message, identity).unwrap();
                let finish = start
                    .state
                    .finish(
                        &mut OsRng,
                        &bytes,
                        response.message,
                        ClientRegistrationFinishParameters::default(),
                    )
                    .unwrap();
                let saved = ServerRegistration::finish(finish.message).serialize();
                record = Some(ServerRegistration::<Suite>::deserialize(&saved).unwrap());
                send(json!({"bytes": hex::encode(finish.export_key)}));
            }
            "register" => {
                let response = ServerRegistration::start(
                    &setup,
                    RegistrationRequest::deserialize(&bytes).unwrap(),
                    identity,
                )
                .unwrap();
                send(json!({"bytes": hex::encode(response.message.serialize())}));
            }
            "save" => {
                let registered = ServerRegistration::finish(
                    RegistrationUpload::<Suite>::deserialize(&bytes).unwrap(),
                );
                // Exercise a stored v3 password record, not just an in-memory object.
                record = Some(
                    ServerRegistration::<Suite>::deserialize(&registered.serialize()).unwrap(),
                );
                send(json!({"saved": true}));
            }
            "login" => {
                let response = ServerLogin::start(
                    &mut OsRng,
                    &setup,
                    record.clone(),
                    CredentialRequest::deserialize(&bytes).unwrap(),
                    identity,
                    ServerLoginStartParameters::default(),
                )
                .unwrap();
                login = Some(response.state);
                send(json!({"bytes": hex::encode(response.message.serialize())}));
            }
            "finish" => {
                let response = login
                    .take()
                    .unwrap()
                    .finish(CredentialFinalization::deserialize(&bytes).unwrap())
                    .unwrap();
                send(json!({"session_key": hex::encode(response.session_key)}));
            }
            _ => panic!("Unknown test operation"),
        }
    }
}
