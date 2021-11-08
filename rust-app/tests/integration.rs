#![cfg_attr(not(target_os = "linux"), no_std)]

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use hex::encode;
    use hyper;
    use hyper::client::connect::HttpConnector;
    use ledger_apdu::APDUCommand;
    use speculos_api::apis;
    use speculos_api::apis::DefaultApi;
    use speculos_api::models::button::*;
    use speculos_api::models::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::process::Command;
    use tokio::test;
    use tokio::time::{sleep, Duration};
    use tokio_retry::strategy::FixedInterval;
    use tokio_retry::Retry;

    use std::env;
    use tokio::sync::Semaphore;

    use blake2::{Blake2b, Digest};
    use ed25519_dalek::{Verifier, Signature, PublicKey};

    static DID_BUILD: AtomicBool = AtomicBool::new(false);
    use lazy_static::lazy_static;
    lazy_static! {
        static ref LEDGER_APP: Semaphore = Semaphore::new(1);
    }

    async fn with_speculos<F, Fut, O>(f: F) -> Option<O>
    where
        F: Fn(apis::DefaultApiClient<HttpConnector>) -> Fut,
        Fut: Future<Output = Option<O> >,
    {
        let speculos_lock = LEDGER_APP.acquire();
        println!("PASSED THE LOCK");

        if !DID_BUILD.load(Ordering::Relaxed) {
            let debug = env::var("DEBUG").unwrap_or_default();
            let features = match debug.as_str() {
                "verbose" => "speculos,extra_debug",
                "none" => "",
                _ => "speculos",
            };
            eprintln!("Building with {}\n", features);
            match Command::new("cargo")
                .args(["build", "-Z", "build-std=core", "--features", features])
                .status()
                .await
                .map(|s| s.success())
            {
                Ok(true) => (),
                _ => {
                    print!("Build Failed; terminating");
                    std::process::exit(1);
                }
            }
            DID_BUILD.store(true, Ordering::Relaxed);
        }

        let _speculos = Command::new("speculos")
            .args([
                "./target/thumbv6m-none-eabi/debug/rust-app",
                "--display",
                "headless",
            ])
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to execute speculos");

        let raw_client = hyper::client::Client::new();
        let client = apis::DefaultApiClient::new(std::rc::Rc::new(
            apis::configuration::Configuration::new(raw_client),
        ));

        let strat = FixedInterval::from_millis(100);
        match Retry::spawn(strat, || async {
            let a = client.events_delete().await;
            a
        })
        .await
        {
            Ok(_) => {}
            Err(_) => {
                panic!("failed to delete previous events");
            }
        }

        let rv = f(client).await;

        core::mem::drop(speculos_lock);

        assert_eq!(rv.is_some(), true);

        rv
    }

    /*#[test]
    async fn run_unit_tests() {
        let debug = env::var("DEBUG").unwrap_or_default();
        let features = match debug.as_str() {
            "verbose" => "speculos,extra_debug",
            _ => "speculos",
        };
        assert_eq!(Some(true), Command::new("cargo")
            .args(["test", "-Z", "build-std=core", "--features", features])
            .status().await.map(|s| s.success()).ok());
    }*/

    // #[test]
    async fn test_provide_pubkey() {
        with_speculos(|client| async move {
            let payload = vec!(0x01,0x00,0x00,0x00,0x00);
            let provide_pubkey = APDUCommand {
                cla: 0,
                ins: 2,
                p1: 0,
                p2: 0,
                data: payload
            };

            let res_async = client.apdu_post(Apdu::new(encode(provide_pubkey.serialize())));

            let btns = async {
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                Some::<()>(())
            };
            let (res, _) = futures::join!(res_async, btns);

            assert_eq!(res.ok(), Some(Apdu { data: "8118ad392b9276e348c1473649a3bbb7ec2b39380e40898d25b55e9e6ee94ca39000".to_string() }));
            client.events_delete().await.ok()?;
            Some(())

        }).await;
        ()
    }

    // #[test]
    async fn test_provide_pubkey_twice() {
        with_speculos(|client| async move {
            let payload = vec!(0x01,0x00,0x00,0x00,0x00);
            let provide_pubkey = APDUCommand {
                cla: 0,
                ins: 2,
                p1: 0,
                p2: 0,
                data: payload
            };

            let res_async = client.apdu_post(Apdu::new(encode(provide_pubkey.serialize())));

            let btns = async {
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                Some(())
            };
            let (res, _) = futures::join!(res_async, btns);

            assert_eq!(res.ok(), Some(Apdu { data: "8118ad392b9276e348c1473649a3bbb7ec2b39380e40898d25b55e9e6ee94ca39000".to_string() }));

            let payload_2 = vec!(0x02,  0x00,0x00,0x00,0x00,  0x00, 0x01, 0x00, 0x00);
            let provide_pubkey_2 = APDUCommand {
                cla: 0,
                ins: 2,
                p1: 0,
                p2: 0,
                data: payload_2
            };

            let res_async_2 = client.apdu_post(Apdu::new(encode(provide_pubkey_2.serialize())));

            let btns = async {
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                Some(())
            };
            let (res_2, _) = futures::join!(res_async_2, btns);

            assert_eq!(res_2.ok(), Some(Apdu { data: "a8b48f8ae7e421a628b926401d358e365fdd614c1b499a11c23f91cc2c614b2c9000".to_string() }));
            client.events_delete().await.ok()?;
            Some(())
        }).await;
        ()
    }

    #[test]
    async fn test_sign() {
        with_speculos(|client| async move {
            let bip32 : Vec<u8> = vec!(0x01,0x00,0x00,0x00,0x00);
            let cmd = br#"
       {"networkId":"mainnet01","payload":{"exec":{"data":{},"code":"(coin.transfer \"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790\" \"9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42\" 11.0)"}},"signers":[{"pubKey":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","clist":[{"args":[],"name":"coin.GAS"},{"args":["83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790","9790d119589a26114e1a42d92598b3f632551c566819ec48e0e8c54dae6ebb42",11],"name":"coin.TRANSFER"}]}],"meta":{"creationTime":1634009214,"ttl":28800,"gasLimit":600,"chainId":"0","gasPrice":1.0e-5,"sender":"83934c0f9b005f378ba3520f9dea952fb0a90e5aa36f1b5ff837d9b30c471790"},"nonce":"\"2021-10-12T03:27:53.700Z\"",
              }"#;
            let payload : Vec<_>= (cmd.len() as u32).to_le_bytes().iter().chain(cmd.iter()).chain(bip32.iter()).cloned().collect();
            // let payload : Vec<_>= cmd.iter().chain(bip32.iter()).cloned().collect();

            let res_async = async {
                let mut res = None;
                for chunk in payload.chunks(230) {

                    let provide_pubkey = APDUCommand {
                        cla: 0,
                        ins: 3,
                        p1: 0,
                        p2: 0,
                        data: chunk.to_vec()
                    };

                    res = Some(client.apdu_post(Apdu::new(encode(provide_pubkey.serialize()))).await);
                }
                res.unwrap()
            };

            let btns = async {
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;

                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Right, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                client.button_button_post(ButtonName::Both, Button { action: Action::PressAndRelease, delay: Some(0.5) }).await.ok()?;
                sleep(Duration::from_millis(2000)).await;
                Some(())
            };
            let (res, _) = futures::join!(res_async, btns);

            let res_str = &res.as_ref().unwrap().data;

            use core::convert::TryInto; 
            let sig1 = hex::decode(&res_str[0..res_str.len()-2]).unwrap();
            print!("Decoded: {:?}\n", sig1);
            let sig = Signature::new(hex::decode(&res_str[0..res_str.len()-4]).unwrap().try_into().unwrap());
            print!("Sig: {:?}\n", sig);
            let key_base = &hex::decode("8118ad392b9276e348c1473649a3bbb7ec2b39380e40898d25b55e9e6ee94ca3").unwrap();
            print!("Key: {:?} {}\n", key_base, key_base.len());
            let key = PublicKey::from_bytes(&hex::decode("8118ad392b9276e348c1473649a3bbb7ec2b39380e40898d25b55e9e6ee94ca3").unwrap()).unwrap();
            use generic_array::{GenericArray, typenum::U64};
            let mut message2 : GenericArray<u8, U64> = Blake2b::digest(cmd);
            let mut message : GenericArray<u8, U64> = Default::default();

            print!("Hash is: {:?}\n", message2);

            assert_eq!(key.verify_strict(message2.as_slice(), &sig).unwrap(), ());
            
            
            Some(())
        }).await;
        ()
    }
}
