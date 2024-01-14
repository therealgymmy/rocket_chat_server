#[macro_use]
extern crate rocket;

use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::State;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::sync::Mutex;

const DATA_FILE: &str = "chat_data.json";

fn load_messages() -> io::Result<Vec<Message>> {
    match File::open(DATA_FILE) {
        Ok(mut file) => {
            let mut data = String::new();
            file.read_to_string(&mut data)?;
            let messages = serde_json::from_str(&data).unwrap_or_else(|_| vec![]);
            Ok(messages)
        }
        Err(_) => Ok(vec![]), // If file doesn't exist, start with an empty vector
    }
}

fn save_messages(messages: &Vec<Message>) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(DATA_FILE)?;

    let data = serde_json::to_string(messages)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
struct Message {
    username: String,
    content: String,
}

struct ChatState {
    messages: Mutex<Vec<Message>>,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct PostMessage {
    username: String,
    content: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct GetMessage {
    username: String,
    content: String,
}

#[post("/message", format = "json", data = "<message>")]
fn post_message(message: Json<PostMessage>, state: &State<ChatState>) {
    let mut messages = state.messages.lock().unwrap();
    messages.push(Message {
        username: message.username.clone(),
        content: message.content.clone(),
    });
    save_messages(&messages).expect("Failed to save messages")
}

#[get("/messages")]
fn get_messages(state: &State<ChatState>) -> Json<Vec<GetMessage>> {
    let messages = state.messages.lock().unwrap();
    Json(
        messages
            .iter()
            .map(|msg| GetMessage {
                username: msg.username.clone(),
                content: msg.content.clone(),
            })
            .collect(),
    )
}

#[launch]
fn rocket() -> _ {
    let chat_state = ChatState {
        messages: Mutex::new(load_messages().expect("Failed to load messages")),
    };
    rocket::build()
        .manage(chat_state)
        .mount("/", routes![index, post_message, get_messages])
}

#[get("/")]
fn index() -> &'static str {
    "Hello, Rocket Chat Server!"
}
