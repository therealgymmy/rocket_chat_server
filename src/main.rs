#[macro_use]
extern crate rocket;

use bcrypt::{hash, verify};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::State;
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use rusqlite::{params, Connection};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn create_db() -> rusqlite::Result<()> {
    let conn = Connection::open("chat.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY,
                  username TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL
         )",
        [],
    )?;
    Ok(())
}

/*
 * User authentication
 */
#[derive(Serialize, Deserialize)]
struct UserRegistration {
    email: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct JwtClaim {
    sub: String,
    exp: usize,
}

struct AuthenticatedUser {
    username: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(
        req: &'r Request<'_>,
    ) -> request::Outcome<AuthenticatedUser, Self::Error> {
        let authorization_header = req.headers().get_one("Authorization");
        println!("debug: token: {:?}", authorization_header);

        let token = match authorization_header {
            Some(header) => {
                // Split the header to separate "Bearer" from the actual token
                let parts: Vec<&str> = header.split_whitespace().collect();
                if parts.len() == 2 && parts[0] == "Bearer" {
                    Some(parts[1])
                } else {
                    None
                }
            }
            None => None,
        };
        match token {
            Some(token) => {
                match decode::<JwtClaim>(
                    &token,
                    &DecodingKey::from_secret("secret_key".as_ref()),
                    &Validation::default(),
                ) {
                    Ok(c) => request::Outcome::Success(AuthenticatedUser {
                        username: c.claims.sub,
                    }),
                    Err(_) => request::Outcome::Error((Status::Unauthorized, ())),
                }
            }
            None => request::Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

fn register_user(email: String, username: String, password: String) -> Result<(), String> {
    // TODO: Save user email into the chat db

    let password_hash = hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string())?;
    let conn = Connection::open("chat.db").map_err(|e| e.to_string())?;

    // let num_rows = conn
    //     .execute(
    //         "SELECT username FROM users WHERE username = ?1",
    //         params![username],
    //     )
    //     .map_err(|e| e.to_string())?;
    // if num_rows > 0 {
    //     return Err("User already exists".to_string());
    // }
    let mut check_user = conn
        .prepare("SELECT username FROM users WHERE username = ?1")
        .map_err(|e| e.to_string())?;
    let user_exists = check_user
        .exists(params![&username])
        .map_err(|e| e.to_string())?;
    println!("dbg: {:?}", user_exists);
    if user_exists {
        // Handle the case where the username already exists, e.g., return an error
        return Err("Username already exists".to_string());
    }

    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        params![username, password_hash],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

fn authenticate_user(username: String, password: String) -> Result<String, String> {
    let conn = Connection::open("chat.db").map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT password_hash FROM users WHERE username = ?1")
        .map_err(|e| e.to_string())?;
    let password_hash: String = stmt
        .query_row(params![username], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    if verify(password, &password_hash).map_err(|e| e.to_string())? {
        // Get the current time as a Unix timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let expiration_time = now
            .checked_add(Duration::from_secs(3600)) // Add 3600 seconds (1 hour) to the current time
            .expect("Invalid timestamp")
            .as_secs();
        let expiration = expiration_time;

        let claims = JwtClaim {
            sub: username,
            exp: expiration as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret_key".as_ref()),
        )
        .map_err(|e| e.to_string())?;
        println!("Returning token: {:?}", token);
        Ok(token)
    } else {
        Err("Invalid username or password".to_string())
    }
}

#[post("/register", format = "json", data = "<user_data>")]
async fn register(user_data: Json<UserRegistration>) -> Json<Result<(), String>> {
    Json(register_user(
        user_data.email.clone(),
        user_data.username.clone(),
        user_data.password.clone(),
    ))
}

#[post("/login", format = "json", data = "<login_data>")]
async fn login(login_data: Json<User>) -> Json<Result<String, String>> {
    Json(authenticate_user(
        login_data.username.clone(),
        login_data.password.clone(),
    ))
}

/*
 * Save and load messages
 */
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

/*
 * Receiving messages and sending messages
 */
#[derive(Serialize, Deserialize, Clone)]
struct Message {
    username: String,
    content: String,
    timestamp: String,
}

struct ChatState {
    messages: Mutex<Vec<Message>>,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct PostMessage {
    username: String,
    content: String,
    timestamp: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct GetMessage {
    username: String,
    content: String,
    timestamp: String,
}

#[post("/message", format = "json", data = "<message>")]
fn post_message(user: AuthenticatedUser, message: Json<PostMessage>, state: &State<ChatState>) {
    let mut messages = state.messages.lock().unwrap();
    messages.push(Message {
        username: message.username.clone(),
        content: message.content.clone(),
        timestamp: message.timestamp.clone(),
    });
    save_messages(&messages).expect("Failed to save messages")
}

#[get("/messages")]
// fn get_messages(state: &State<ChatState>) -> Json<Vec<GetMessage>> {
fn get_messages(user: AuthenticatedUser, state: &State<ChatState>) -> Json<Vec<GetMessage>> {
    let messages = state.messages.lock().unwrap();
    Json(
        messages
            .iter()
            .map(|msg| GetMessage {
                username: msg.username.clone(),
                content: msg.content.clone(),
                timestamp: msg.timestamp.clone(),
            })
            .collect(),
    )
}

#[get("/")]
fn index() -> &'static str {
    "Hello, Rocket Chat Server!"
}

#[launch]
fn rocket() -> _ {
    create_db().expect("Failed to create database");

    // This is only needed for local testing using browser for react-native frontend
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::some_exact(&["http://localhost:19006"]))
        .allowed_headers(AllowedHeaders::some(&[
            "Authorization",
            "Content-Type",
            // Add other headers as needed
        ]))
        .to_cors()
        .unwrap();
    let chat_state = ChatState {
        messages: Mutex::new(load_messages().expect("Failed to load messages")),
    };
    rocket::build()
        .configure(rocket::Config {
            address: IpAddr::from_str("0.0.0.0").unwrap(),
            ..Default::default()
        })
        .attach(cors)
        .manage(chat_state)
        .mount(
            "/",
            routes![index, register, login, post_message, get_messages],
        )
}
