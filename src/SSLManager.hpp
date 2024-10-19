#pragma once
#ifndef SSLMANAGER_HPP
#define SSLMANAGER_HPP

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <sys/stat.h>
#include <string>
#include <cstring>
#include <errno.h>

#include "Logger.hpp"

class SSLManager {
public:
    SSLManager();
    ~SSLManager();

    SSL_CTX* GetContext();
    bool IsCertificateSelfSigned(const std::string& certFile);

private:
    SSL_CTX* ssl_ctx_;

    void InitSSL();
    void CleanupSSL();
    void GenerateSelfSignedCertificate();
    bool FileExists(const std::string& filename);
};

SSLManager::SSLManager() : ssl_ctx_(nullptr) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    InitSSL();
}

SSLManager::~SSLManager() {
    CleanupSSL();
}

SSL_CTX* SSLManager::GetContext() {
    return ssl_ctx_;
}

void SSLManager::InitSSL() {
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        Logger::log("Failed to create SSL context: " + std::string(buf), Logger::Level::SSL);
        exit(EXIT_FAILURE);
    }

    // Disabling SSL to ensure only TLS is used
    SSL_CTX_set_options(ssl_ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Checking if certs exist, if not generate self-signed certificate
    if (!FileExists("crt/server.crt") || !FileExists("crt/server.key")) GenerateSelfSignedCertificate();

    // Load certificates from files
    if (SSL_CTX_use_certificate_file(ssl_ctx_, "crt/server.crt", SSL_FILETYPE_PEM) <= 0) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        Logger::log("Failed to load certificate: " + std::string(buf), Logger::Level::SSL);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, "crt/server.key", SSL_FILETYPE_PEM) <= 0) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        Logger::log("Failed to load private key: " + std::string(buf), Logger::Level::SSL);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        Logger::log("Private key does not match the public certificate", Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }

    // Check if the certificate is self-signed, would like to get Let's Encrypt in the future
    if (IsCertificateSelfSigned("crt/server.crt")) {
        Logger::log("Warning: Using a self-signed certificate. This is not secure and should not be used in production.", Logger::Level::WARNING);
    }
}

void SSLManager::CleanupSSL() {
    SSL_CTX_free(ssl_ctx_);
    EVP_cleanup();
}

bool SSLManager::FileExists(const std::string& filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

void SSLManager::GenerateSelfSignedCertificate() {
    Logger::log("Generating self-signed certificate...", Logger::Level::INFO);

    // Create the crt directory if it doesn't exist
    mkdir("crt", 0755);

    // Generate key pair using EVP APIs
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) {
        Logger::log("Failed to create EVP_PKEY_CTX for key generation", Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        Logger::log("Failed to initialize key generation context", Logger::Level::ERROR);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        Logger::log("Failed to set RSA key size", Logger::Level::ERROR);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        Logger::log("Key generation failed", Logger::Level::ERROR);
        EVP_PKEY_CTX_free(pctx);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);

    // Generate certificate
    X509* x509 = X509_new();
    if (!x509) {
        Logger::log("Failed to create X509 structure", Logger::Level::ERROR);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
    X509_set_pubkey(x509, pkey);

    // Might let the user specify these in the future
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"GB", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"State", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char*)"City", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"Jadmium", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"Self-Signed Cert", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Sign the certificate
    if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
        Logger::log("Failed to sign certificate", Logger::Level::ERROR);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    // Save the private key to file
    FILE* pkey_file = fopen("crt/server.key", "wb");
    if (!pkey_file) {
        Logger::log("Unable to open file for writing private key: " + std::string(strerror(errno)), Logger::Level::ERROR);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    if (PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        Logger::log("Failed to write private key to file", Logger::Level::ERROR);
        fclose(pkey_file);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    fclose(pkey_file);

    // Save the certificate to file
    FILE* x509_file = fopen("crt/server.crt", "wb");
    if (!x509_file) {
        Logger::log("Unable to open file for writing certificate: " + std::string(strerror(errno)), Logger::Level::ERROR);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    if (PEM_write_X509(x509_file, x509) != 1) {
        Logger::log("Failed to write certificate to file", Logger::Level::ERROR);
        fclose(x509_file);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }
    fclose(x509_file);

    // Free resources
    X509_free(x509);
    EVP_PKEY_free(pkey);

    Logger::log("Self-signed certificate generated at crt/server.crt and crt/server.key", Logger::Level::INFO);
}

bool SSLManager::IsCertificateSelfSigned(const std::string& certFile) {
    FILE* file = fopen(certFile.c_str(), "r");
    if (!file) {
        Logger::log("Failed to open certificate file for self-signed check: " + std::string(strerror(errno)), Logger::Level::ERROR);
        return false;
    }

    X509* cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);

    if (!cert) {
        Logger::log("Failed to read certificate for self-signed check", Logger::Level::ERROR);
        return false;
    }

    // Check if certificate is self-signed by comparing subject and issuer names
    bool is_self_signed = (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0);
    X509_free(cert);

    return is_self_signed;
}

#endif // SSLMANAGER_HPP