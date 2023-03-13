use crate::utils::{MpscTracingSender, StringError};
use std::fmt;
use tokio::sync::{mpsc, oneshot};
use tracing::trace;

pub type ThreadedCall<T> = Box<dyn FnOnce(&mut T) + Send + 'static>;
pub type ThreadedCallSender<T> = MpscTracingSender<ThreadedCall<T>>;
pub type ThreadedCallReceiver<T> = mpsc::Receiver<ThreadedCall<T>>;

// Implement blank Debug for ThreadedCallSender
impl<T> std::fmt::Debug for ThreadedCallSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

/// Channel for remote calls
pub struct ThreadedCallChannel<T: ?Sized> {
    pub tx: ThreadedCallSender<T>,
    pub rx: ThreadedCallReceiver<T>,
}

impl<T: ?Sized> Default for ThreadedCallChannel<T> {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self { tx: tx.into(), rx }
    }
}

impl<T: ?Sized> fmt::Debug for ThreadedCallChannel<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

pub async fn make_threaded_call<'a, T: ?Sized, R: Send + Sized + 'static>(
    tx: &mut ThreadedCallSender<T>,
    f: impl FnOnce(&mut T) -> R + Send + Sized + 'static,
    tag: &str,
) -> Result<R, StringError> {
    let (r_tx, r_rx) = oneshot::channel::<R>();
    tx.send(
        Box::new(move |v| {
            if r_tx.send(f(v)).is_err() {
                trace!("ThreadedCall fail to send result");
            }
        }),
        tag,
    )
    .await
    .map_err(|_| StringError("ThreadedCall fail to send call".to_owned()))?;

    let r = r_rx
        .await
        .map_err(|_| StringError("ThreadedCall fail to get result".to_owned()))?;
    Ok(r)
}

#[cfg(test)]
mod test {
    use super::*;

    struct Callee {
        channel: ThreadedCallChannel<Callee>,
        value: u64,
    }

    impl Callee {
        fn new(v: u64) -> Self {
            Self {
                channel: Default::default(),
                value: v,
            }
        }

        fn call(&self) -> u32 {
            self.value as u32
        }

        fn call_set(&mut self, v: u8) {
            self.value = v as u64;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn threaded_call() {
        let mut callee = Callee::new(555);
        let mut tx = callee.channel.tx.clone();

        let join_handle = tokio::spawn({
            async move {
                let f = callee.channel.rx.recv().await.unwrap();
                f(&mut callee);
                let f = callee.channel.rx.recv().await.unwrap();
                f(&mut callee);
                callee.value
            }
        });
        let rg = make_threaded_call(&mut tx, |v| v.call(), "Test get").await;
        let rs = make_threaded_call(&mut tx, |v| v.call_set(5), "Test set").await;
        let join_r = join_handle.await.map_err(|e| e.to_string());

        assert_eq!((rg, rs, join_r), (Ok(555), Ok(()), Ok(5)));
    }
}
