//! Native Windows certificate store helpers.
//!
//! RelayGate only manages the per-user Windows trusted Root store.
//!
//! CurrentUser\Root is enough for the normal browser trust path and avoids
//! administrator/UAC flows.

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, fs, path::Path};

    use anyhow::{bail, Context, Result};
    use serde::Serialize;
    use sha1::{Digest, Sha1};

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub(crate) enum RootStoreScope {
        CurrentUser,
    }

    impl RootStoreScope {
        pub(crate) fn label(self) -> &'static str {
            match self {
                Self::CurrentUser => "CurrentUser\\Root",
            }
        }

        fn system_store_flag(self) -> u32 {
            match self {
                Self::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    pub(crate) struct NativeRelayGateCa {
        pub(crate) thumbprint: String,
        pub(crate) subject: String,
        pub(crate) issuer: String,
        pub(crate) store: String,
        pub(crate) not_before_unix_secs: i64,
        pub(crate) not_after_unix_secs: i64,
        pub(crate) is_current: bool,
    }

    #[derive(Debug, Clone, Copy, Serialize)]
    pub(crate) struct NativeDeleteResult {
        pub(crate) before: usize,
        pub(crate) after: usize,
    }

    pub(crate) fn cert_thumbprint_from_path(path: &Path) -> Result<String> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read certificate file: {}", path.display()))?;
        let der = cert_file_bytes_to_der(&bytes)?;
        Ok(sha1_hex_upper(&der))
    }

    pub(crate) fn add_certificate_bytes_to_root(
        scope: RootStoreScope,
        cert_bytes: &[u8],
    ) -> Result<String> {
        let der = cert_file_bytes_to_der(cert_bytes)?;
        let thumbprint = sha1_hex_upper(&der);
        let der_len = u32::try_from(der.len()).context("certificate DER is too large")?;

        with_root_store(scope, 0, |store| {
            let context = unsafe {
                CertCreateCertificateContext(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    der.as_ptr(),
                    der_len,
                )
            };
            if context.is_null() {
                bail!("failed to create certificate context for Windows store import");
            }
            let context = OwnedCertContext::new(context);

            let ok = unsafe {
                CertAddCertificateContextToStore(
                    store,
                    context.context,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                bail!(
                    "failed to add certificate to Windows store {}",
                    scope.label()
                );
            }

            Ok(())
        })?;

        Ok(thumbprint)
    }

    pub(crate) fn root_locations_for_thumbprint(thumbprint: &str) -> Result<Vec<String>> {
        let thumbprint = normalize_thumbprint(thumbprint)?;
        let mut locations = Vec::new();
        if thumbprint_exists(RootStoreScope::CurrentUser, &thumbprint, false)? {
            locations.push(RootStoreScope::CurrentUser.label().to_string());
        }
        Ok(locations)
    }

    pub(crate) fn root_diagnostics_for_thumbprint(thumbprint: &str) -> Result<Vec<String>> {
        let thumbprint = normalize_thumbprint(thumbprint)?;
        let mut items = Vec::new();
        let count = thumbprint_match_count(RootStoreScope::CurrentUser, &thumbprint, false)?;
        items.push(format!(
            "{}:count={count}",
            RootStoreScope::CurrentUser.label()
        ));
        Ok(items)
    }

    pub(crate) fn relaygate_cas(
        current_thumbprint: Option<&str>,
    ) -> Result<Vec<NativeRelayGateCa>> {
        let current = current_thumbprint
            .map(normalize_thumbprint)
            .transpose()?
            .unwrap_or_default();
        relaygate_cas_in_scope(RootStoreScope::CurrentUser, &current)
    }

    pub(crate) fn thumbprint_exists(
        scope: RootStoreScope,
        thumbprint: &str,
        require_relaygate_name: bool,
    ) -> Result<bool> {
        Ok(thumbprint_match_count(scope, thumbprint, require_relaygate_name)? > 0)
    }

    pub(crate) fn delete_thumbprint(
        scope: RootStoreScope,
        thumbprint: &str,
        require_relaygate_name: bool,
    ) -> Result<NativeDeleteResult> {
        let thumbprint = normalize_thumbprint(thumbprint)?;
        with_root_store(scope, 0, |store| {
            let mut before = 0usize;
            let mut contexts = Vec::new();
            let mut cursor = CertCursor::new(store);

            while let Some(context) = cursor.next()? {
                let item_thumbprint = thumbprint_from_context(context)?;
                if item_thumbprint != thumbprint {
                    continue;
                }
                if require_relaygate_name && !context_has_relaygate_name(context)? {
                    continue;
                }

                before += 1;
                let duplicate = unsafe { CertDuplicateCertificateContext(context) };
                if duplicate.is_null() {
                    bail!("failed to duplicate certificate context for removal");
                }
                contexts.push(OwnedCertContext::new(duplicate));
            }

            drop(cursor);

            for context in contexts {
                context.delete()?;
            }

            let after = thumbprint_match_count_in_store(store, &thumbprint, false)?;
            Ok(NativeDeleteResult { before, after })
        })
    }

    fn thumbprint_match_count(
        scope: RootStoreScope,
        thumbprint: &str,
        require_relaygate_name: bool,
    ) -> Result<usize> {
        let thumbprint = normalize_thumbprint(thumbprint)?;
        with_root_store(scope, CERT_STORE_READONLY_FLAG, |store| {
            let mut count = 0usize;
            let mut cursor = CertCursor::new(store);
            while let Some(context) = cursor.next()? {
                let item_thumbprint = thumbprint_from_context(context)?;
                if item_thumbprint == thumbprint
                    && (!require_relaygate_name || context_has_relaygate_name(context)?)
                {
                    count += 1;
                }
            }
            Ok(count)
        })
    }

    fn thumbprint_match_count_in_store(
        store: HCERTSTORE,
        thumbprint: &str,
        require_relaygate_name: bool,
    ) -> Result<usize> {
        let mut count = 0usize;
        let mut cursor = CertCursor::new(store);
        while let Some(context) = cursor.next()? {
            let item_thumbprint = thumbprint_from_context(context)?;
            if item_thumbprint == thumbprint
                && (!require_relaygate_name || context_has_relaygate_name(context)?)
            {
                count += 1;
            }
        }
        Ok(count)
    }

    fn relaygate_cas_in_scope(
        scope: RootStoreScope,
        current: &str,
    ) -> Result<Vec<NativeRelayGateCa>> {
        with_root_store(scope, CERT_STORE_READONLY_FLAG, |store| {
            let mut items = Vec::new();
            let mut cursor = CertCursor::new(store);
            while let Some(context) = cursor.next()? {
                if !context_has_relaygate_name(context)? {
                    continue;
                }
                let thumbprint = thumbprint_from_context(context)?;
                let (not_before, not_after) = cert_validity_unix_secs(context)?;
                items.push(NativeRelayGateCa {
                    is_current: !current.is_empty() && thumbprint == current,
                    thumbprint,
                    subject: cert_name_string(context, 0)?,
                    issuer: cert_name_string(context, CERT_NAME_ISSUER_FLAG)?,
                    store: scope.label().to_string(),
                    not_before_unix_secs: not_before,
                    not_after_unix_secs: not_after,
                });
            }
            Ok(items)
        })
    }

    fn context_has_relaygate_name(context: *const CERT_CONTEXT) -> Result<bool> {
        let subject = cert_name_string(context, 0)?;
        let issuer = cert_name_string(context, CERT_NAME_ISSUER_FLAG)?;
        Ok(subject.contains("RelayGate") || issuer.contains("RelayGate"))
    }

    fn with_root_store<T>(
        scope: RootStoreScope,
        extra_flags: u32,
        callback: impl FnOnce(HCERTSTORE) -> Result<T>,
    ) -> Result<T> {
        let name = wide_null("Root");
        let flags = scope.system_store_flag()
            | CERT_STORE_OPEN_EXISTING_FLAG
            | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG
            | extra_flags;
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                flags,
                name.as_ptr().cast(),
            )
        };
        if store.is_null() {
            bail!("failed to open Windows certificate store {}", scope.label());
        }

        let result = callback(store);
        unsafe {
            CertCloseStore(store, 0);
        }
        result
    }

    struct CertCursor {
        store: HCERTSTORE,
        previous: *const CERT_CONTEXT,
        finished: bool,
    }

    impl CertCursor {
        fn new(store: HCERTSTORE) -> Self {
            Self {
                store,
                previous: std::ptr::null(),
                finished: false,
            }
        }

        fn next(&mut self) -> Result<Option<*const CERT_CONTEXT>> {
            if self.finished {
                return Ok(None);
            }
            let context = unsafe { CertEnumCertificatesInStore(self.store, self.previous) };
            self.previous = context;
            if context.is_null() {
                self.finished = true;
                return Ok(None);
            }
            Ok(Some(context))
        }
    }

    impl Drop for CertCursor {
        fn drop(&mut self) {
            if !self.previous.is_null() && !self.finished {
                unsafe {
                    CertFreeCertificateContext(self.previous);
                }
                self.previous = std::ptr::null();
            }
        }
    }

    struct OwnedCertContext {
        context: *const CERT_CONTEXT,
    }

    impl OwnedCertContext {
        fn new(context: *const CERT_CONTEXT) -> Self {
            Self { context }
        }

        fn delete(mut self) -> Result<()> {
            let ok = unsafe { CertDeleteCertificateFromStore(self.context) };
            self.context = std::ptr::null();
            if ok == 0 {
                bail!("failed to delete certificate from Windows store");
            }
            Ok(())
        }
    }

    impl Drop for OwnedCertContext {
        fn drop(&mut self) {
            if !self.context.is_null() {
                unsafe {
                    CertFreeCertificateContext(self.context);
                }
                self.context = std::ptr::null();
            }
        }
    }

    fn thumbprint_from_context(context: *const CERT_CONTEXT) -> Result<String> {
        let mut size = 0u32;
        let ok = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_HASH_PROP_ID,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if ok == 0 || size == 0 {
            bail!("failed to query certificate thumbprint size");
        }

        let mut bytes = vec![0u8; size as usize];
        let ok = unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_HASH_PROP_ID,
                bytes.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            bail!("failed to read certificate thumbprint");
        }
        bytes.truncate(size as usize);
        Ok(hex_upper(&bytes))
    }

    fn cert_name_string(context: *const CERT_CONTEXT, flags: u32) -> Result<String> {
        let chars = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            )
        };
        if chars <= 1 {
            return Ok(String::new());
        }

        let mut buffer = vec![0u16; chars as usize];
        let written = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                chars,
            )
        };
        if written == 0 {
            bail!("failed to read certificate display name");
        }
        let len = written.saturating_sub(1) as usize;
        Ok(String::from_utf16_lossy(&buffer[..len]))
    }

    fn cert_validity_unix_secs(context: *const CERT_CONTEXT) -> Result<(i64, i64)> {
        let cert_info = unsafe { (*context).p_cert_info };
        if cert_info.is_null() {
            bail!("certificate context does not include CERT_INFO");
        }
        let info = unsafe { &*cert_info };
        Ok((
            filetime_to_unix_secs(info.not_before),
            filetime_to_unix_secs(info.not_after),
        ))
    }

    fn cert_file_bytes_to_der(bytes: &[u8]) -> Result<Vec<u8>> {
        let text = std::str::from_utf8(bytes).ok();
        if let Some(text) = text {
            if text.contains("-----BEGIN CERTIFICATE-----") {
                let body = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>();
                return base64_simple_decode(&body);
            }
        }
        Ok(bytes.to_vec())
    }

    fn normalize_thumbprint(thumbprint: &str) -> Result<String> {
        let normalized = thumbprint
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .map(|ch| ch.to_ascii_uppercase())
            .collect::<String>();
        if normalized.len() != 40 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("invalid certificate thumbprint");
        }
        Ok(normalized)
    }

    fn sha1_hex_upper(bytes: &[u8]) -> String {
        let digest = Sha1::digest(bytes);
        hex_upper(&digest)
    }

    fn hex_upper(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn filetime_to_unix_secs(filetime: FILETIME) -> i64 {
        let ticks = ((filetime.dw_high_date_time as u64) << 32) | filetime.dw_low_date_time as u64;
        ((ticks / 10_000_000) as i64) - 11_644_473_600
    }

    fn base64_simple_decode(input: &str) -> Result<Vec<u8>> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = Vec::new();
        let mut chunk = Vec::new();

        for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
            if byte == b'=' {
                chunk.push(64);
            } else if let Some(index) = TABLE.iter().position(|candidate| *candidate == byte) {
                chunk.push(index as u8);
            } else {
                bail!("invalid base64 character in certificate PEM");
            }

            if chunk.len() == 4 {
                decode_base64_chunk(&chunk, &mut output);
                chunk.clear();
            }
        }

        if !chunk.is_empty() {
            bail!("invalid base64 length in certificate PEM");
        }

        Ok(output)
    }

    fn decode_base64_chunk(chunk: &[u8], output: &mut Vec<u8>) {
        let first = chunk[0];
        let second = chunk[1];
        let third = chunk[2];
        let fourth = chunk[3];

        output.push((first << 2) | (second >> 4));
        if third != 64 {
            output.push(((second & 0x0F) << 4) | (third >> 2));
        }
        if fourth != 64 {
            output.push(((third & 0x03) << 6) | fourth);
        }
    }

    type BOOL = i32;
    type DWORD = u32;
    type HCERTSTORE = *mut c_void;
    type HcryptprovLegacy = usize;

    const X509_ASN_ENCODING: DWORD = 0x0000_0001;
    const PKCS_7_ASN_ENCODING: DWORD = 0x0001_0000;
    const CERT_STORE_PROV_SYSTEM_W: *const i8 = 10usize as *const i8;
    const CERT_SYSTEM_STORE_CURRENT_USER: DWORD = 0x0001_0000;
    const CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG: DWORD = 0x0000_0004;
    const CERT_STORE_OPEN_EXISTING_FLAG: DWORD = 0x0000_4000;
    const CERT_STORE_READONLY_FLAG: DWORD = 0x0000_8000;
    const CERT_STORE_ADD_REPLACE_EXISTING: DWORD = 3;
    const CERT_HASH_PROP_ID: DWORD = 3;
    const CERT_NAME_ISSUER_FLAG: DWORD = 0x0000_0001;
    const CERT_NAME_SIMPLE_DISPLAY_TYPE: DWORD = 4;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FILETIME {
        dw_low_date_time: DWORD,
        dw_high_date_time: DWORD,
    }

    #[repr(C)]
    struct CRYPT_DATA_BLOB {
        cb_data: DWORD,
        pb_data: *mut u8,
    }

    #[repr(C)]
    struct CRYPT_ALGORITHM_IDENTIFIER {
        psz_obj_id: *mut i8,
        parameters: CRYPT_DATA_BLOB,
    }

    #[repr(C)]
    struct CRYPT_BIT_BLOB {
        cb_data: DWORD,
        pb_data: *mut u8,
        c_unused_bits: DWORD,
    }

    #[repr(C)]
    struct CERT_PUBLIC_KEY_INFO {
        algorithm: CRYPT_ALGORITHM_IDENTIFIER,
        public_key: CRYPT_BIT_BLOB,
    }

    #[repr(C)]
    struct CERT_INFO {
        dw_version: DWORD,
        serial_number: CRYPT_DATA_BLOB,
        signature_algorithm: CRYPT_ALGORITHM_IDENTIFIER,
        issuer: CRYPT_DATA_BLOB,
        not_before: FILETIME,
        not_after: FILETIME,
        subject: CRYPT_DATA_BLOB,
        subject_public_key_info: CERT_PUBLIC_KEY_INFO,
        issuer_unique_id: CRYPT_BIT_BLOB,
        subject_unique_id: CRYPT_BIT_BLOB,
        c_extension: DWORD,
        rg_extension: *mut c_void,
    }

    #[repr(C)]
    struct CERT_CONTEXT {
        dw_cert_encoding_type: DWORD,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: DWORD,
        p_cert_info: *const CERT_INFO,
        h_cert_store: HCERTSTORE,
    }

    #[link(name = "Crypt32")]
    extern "system" {
        fn CertOpenStore(
            lpsz_store_provider: *const i8,
            dw_msg_and_cert_encoding_type: DWORD,
            h_crypt_prov: HcryptprovLegacy,
            dw_flags: DWORD,
            pv_para: *const c_void,
        ) -> HCERTSTORE;
        fn CertCloseStore(h_cert_store: HCERTSTORE, dw_flags: DWORD) -> BOOL;
        fn CertEnumCertificatesInStore(
            h_cert_store: HCERTSTORE,
            p_prev_cert_context: *const CERT_CONTEXT,
        ) -> *const CERT_CONTEXT;
        fn CertFreeCertificateContext(p_cert_context: *const CERT_CONTEXT) -> BOOL;
        fn CertDuplicateCertificateContext(
            p_cert_context: *const CERT_CONTEXT,
        ) -> *const CERT_CONTEXT;
        fn CertDeleteCertificateFromStore(p_cert_context: *const CERT_CONTEXT) -> BOOL;
        fn CertCreateCertificateContext(
            dw_cert_encoding_type: DWORD,
            pb_cert_encoded: *const u8,
            cb_cert_encoded: DWORD,
        ) -> *const CERT_CONTEXT;
        fn CertAddCertificateContextToStore(
            h_cert_store: HCERTSTORE,
            p_cert_context: *const CERT_CONTEXT,
            dw_add_disposition: DWORD,
            pp_store_context: *mut *const CERT_CONTEXT,
        ) -> BOOL;
        fn CertGetCertificateContextProperty(
            p_cert_context: *const CERT_CONTEXT,
            dw_prop_id: DWORD,
            pv_data: *mut c_void,
            pcb_data: *mut DWORD,
        ) -> BOOL;
        fn CertGetNameStringW(
            p_cert_context: *const CERT_CONTEXT,
            dw_type: DWORD,
            dw_flags: DWORD,
            pv_type_para: *const c_void,
            psz_name_string: *mut u16,
            cch_name_string: DWORD,
        ) -> DWORD;
    }

    #[cfg(test)]
    mod tests {
        use super::{base64_simple_decode, normalize_thumbprint};

        #[test]
        fn normalizes_thumbprint_spacing_and_case() {
            let normalized =
                normalize_thumbprint("aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd")
                    .unwrap();
            assert_eq!(normalized, "AABBCCDDEEFF00112233445566778899AABBCCDD");
        }

        #[test]
        fn decodes_base64_with_padding() {
            let decoded = base64_simple_decode("SGVsbG8=").unwrap();
            assert_eq!(decoded, b"Hello");
        }
    }
}

#[cfg(windows)]
pub(crate) use imp::*;
