use actix_web::{Responder, get};

// Define a handler function for the web request
#[get("/")]
async fn index() -> impl Responder {
    "Hello, Actix!"
}
