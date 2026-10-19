//! Windows Hello check before the remembered master password is used. A no-op elsewhere.

#[cfg(windows)]
mod imp {
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{UserConsentVerificationResult as R, UserConsentVerifier, UserConsentVerifierAvailability},
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
    };
    use windows_future::IAsyncOperation;

    pub fn available() -> bool {
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .map(|a| a == UserConsentVerifierAvailability::Available)
            .unwrap_or(false)
    }

    /// Blocks until the user answers the prompt, which is parented to `hwnd`.
    pub fn verify(hwnd: isize, message: &str) -> Result<(), String> {
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>().map_err(|e| e.message())?;
        let op: IAsyncOperation<R> = unsafe {
            interop.RequestVerificationForWindowAsync(HWND(hwnd as *mut core::ffi::c_void), &HSTRING::from(message))
        }
        .map_err(|e| e.message())?;
        match op.join().map_err(|e| e.message())? {
            R::Verified => Ok(()),
            R::Canceled => Err("Windows Hello was cancelled".into()),
            R::RetriesExhausted => Err("Too many attempts. Enter your master password".into()),
            R::DeviceBusy => Err("Windows Hello is busy. Try again".into()),
            _ => Err("Windows Hello isn't available. Enter your master password".into()),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn available() -> bool {
        false
    }

    pub fn verify(_hwnd: isize, _message: &str) -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{available, verify};

/// The native window handle the Hello prompt is attached to (0 where there's none).
pub fn window_handle(window: &tauri::WebviewWindow) -> isize {
    #[cfg(windows)]
    {
        window.hwnd().map(|h| h.0 as isize).unwrap_or(0)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        0
    }
}
