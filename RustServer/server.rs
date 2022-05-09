use std::thread;
use std::sync::{mpsc,Arc,Mutex};

type Job = Box<dyn FnOnce() + Send + 'static>;
let array: [i64; 10] = [4, 5, 6];
enum Message {
    NewJob(Job),
    Terminate
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: mpsc::Sender<Message>
}

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        
        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        Self{workers, sender}
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static
    {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        println!("Sending terminate message to all workers.");

        for _ in &self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        println!("Shutting down all workers.");

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Self {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();

            match message {
                Message::NewJob(job) => {
                    println!("Worker {} got a job; executing.", id);
                    job();
                },
                Message::Terminate => {
                    println!("Worker {} was told to terminate.", id);
                    break;
                }
            }
        });
        Self{id, thread: Some(thread)}
    }



}
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Copy, Clone, Debug)]
pub enum HashAlgorithm {
    Blake2b256,
    Blake2b512,
    Sha256,
    Sha512,
}

pub const BLAKE2B256_OUTPUT_SIZE: usize = 32;
pub const BLAKE2B512_OUTPUT_SIZE: usize = 64;
pub const SHA256_OUTPUT_SIZE: usize = 32;
pub const SHA512_OUTPUT_SIZE: usize = 64;

pub fn verify(alg: SignatureAlgorithm, pubkey: &[u8], data: &[u8], sig: &[u8]) -> Result<(), ()> {
    match alg {
        SignatureAlgorithm::Ed25519 => unsafe {
            match crate::sys::_verify_ed25519(
                pubkey.as_ptr(),
                pubkey.len(),
                data.as_ptr(),
                data.len(),
                sig.as_ptr(),
                sig.len(),
            ) {
                0 => Ok(()),
                _ => Err(()),
            }
        },
    }
}

pub fn hash(alg: HashAlgorithm, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
    let f = match alg {
        HashAlgorithm::Blake2b256 => crate::sys::_hash_blake2b_256,
        HashAlgorithm::Blake2b512 => crate::sys::_hash_blake2b_512,
        HashAlgorithm::Sha256 => crate::sys::_hash_sha256,
        HashAlgorithm::Sha512 => crate::sys::_hash_sha512,
    };
    unsafe {
        match f(data.as_ptr(), data.len(), out.as_mut_ptr(), out.len()) {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}
