cmake_minimum_required(VERSION 3.16)
project(ed25519 C)

add_library(ed25519 STATIC
    add_scalar.c
    fe.c
    ge.c
    keypair.c
    sc.c
    seed.c
    sha512.c
    sign.c
    verify.c)

target_include_directories(ed25519 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# key_exchange.c is omitted — we don't need Diffie-Hellman

add_library(ed25519::ed25519 ALIAS ed25519)
