extern crate tokio;
extern crate log;
extern crate url;
extern crate serde;

use serde::{Serialize, Deserialize};
use futures_util::{future, pin_mut,StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use std::time::{SystemTime, UNIX_EPOCH};
use log::info;
use url::Url;
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};
use hex;

#[derive(Debug)]
struct ApiKeys {
    api_key: String,
    user_id: String,
    secret: String
}

#[derive(Debug)]
struct Signature {
    timestamp: u64,
    hmac_signature: String
}

#[derive(Serialize, Deserialize, Debug)]
struct Auth_OBJ {
    key: String,
    signature: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct API_Auth {
    e: String,
    auth: Auth_OBJ,
    oid: String
}

fn create_signature(key: String, secret: String) -> Signature{
    let mut _timestamp = 0;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => _timestamp = n.as_secs(),
        Err(_) => print!("Error")
    }
    let mut first_part_key = _timestamp.to_string().to_owned();
    let borrowed_key = &key;
    first_part_key.push_str(borrowed_key);
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_varkey(first_part_key.as_bytes())
        .expect("Something");
    let mut _ts =  _timestamp.to_string();
    mac.update(_ts.as_bytes());
    let result = mac.finalize();
    return  Signature{
        timestamp: _timestamp,
        hmac_signature: hex::encode(result.into_bytes().as_slice().to_vec())
    }

}

fn get_signature(api: ApiKeys) -> String{
    let sing = create_signature(api.api_key.to_owned(), api.secret.to_owned());
    let  auth_k = Auth_OBJ{
        key: api.api_key,
        signature: sing.hmac_signature.to_uppercase(),
        timestamp: sing.timestamp.to_string()
    };
    let api_auth = API_Auth{
        e: String::from("auth"),
        auth: auth_k,
        oid: String::from("auth")
    };
    return serde_json::to_string(&api_auth).unwrap();
}

#[tokio::main]
async fn main() {
    let connect_addres = "wss://ws.cex.io/ws/";
    let url = Url::parse(&connect_addres).unwrap();
    let _api_keys = ApiKeys{api_key: String::from(API_KEY),
                            user_id: String::from(USER_ID),
                            secret: String::from(SECRET)};
    let (ws_stream, _) = connect_async(url)
        .await.expect("Failed to connect");
    let (mut write, read) = ws_stream.split();

    let sign =  get_signature(_api_keys);
    println!("{}", sign);
    write.send(Message::Text(sign)).await.expect("Failed to send");
            
    let ws_to_stout = {
        read.for_each(| message| async {
            let data = message.unwrap().into_data();
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };
    ws_to_stout.await;

}
