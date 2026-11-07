//! Test-only OPAQUE peer over private stdio. It opens no network listener and
//! shares no server implementation with the public extension. All accounts and
//! keys are ephemeral fixtures. Never use this as an authentication service.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use opaque_client::DefaultCipherSuite as Suite;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{self, BufRead, Write},
};

fn main() {
    let mut rng = UnwrapErr(SysRng);
    let setup = ServerSetup::<Suite>::new(&mut rng);
    let mut records = HashMap::new();
    let mut pending = HashMap::new();
    let mut next = 0u64;
    for line in io::stdin().lock().lines() {
        let q: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let result = match q["op"].as_str().unwrap() {
            "enroll" => {
                let identity = q["user_id"].as_str().unwrap();
                let password = q["password"].as_str().unwrap().as_bytes();
                let start = ClientRegistration::<Suite>::start(&mut rng, password).unwrap();
                let response =
                    ServerRegistration::start(&setup, start.message, identity.as_bytes()).unwrap();
                let finish = start
                    .state
                    .finish(
                        &mut rng,
                        password,
                        response.message,
                        ClientRegistrationFinishParameters::default(),
                    )
                    .unwrap();
                records.insert(
                    identity.to_owned(),
                    ServerRegistration::finish(finish.message),
                );
                json!({"ok": true})
            }
            "start" => {
                let identity = q["user_id"].as_str().unwrap();
                let request = B64
                    .decode(q["credential_request"].as_str().unwrap())
                    .unwrap();
                let response = ServerLogin::start(
                    &mut rng,
                    &setup,
                    records.get(identity).cloned(),
                    CredentialRequest::deserialize(&request).unwrap(),
                    identity.as_bytes(),
                    ServerLoginParameters::default(),
                )
                .unwrap();
                next += 1;
                let id = next.to_string();
                pending.insert(id.clone(), response.state);
                json!({"state_id": id, "credential_response": B64.encode(response.message.serialize())})
            }
            "finish" => {
                let state = pending.remove(q["state_id"].as_str().unwrap()).unwrap();
                let message = B64
                    .decode(q["credential_finalization"].as_str().unwrap())
                    .unwrap();
                match state.finish(
                    CredentialFinalization::deserialize(&message).unwrap(),
                    ServerLoginParameters::default(),
                ) {
                    Ok(result) => json!({"session_key": B64.encode(result.session_key)}),
                    Err(_) => json!({"error": "OPAQUE finalization rejected"}),
                }
            }
            _ => panic!("Unknown fixture command"),
        };
        println!("{result}");
        io::stdout().flush().unwrap();
    }
}
