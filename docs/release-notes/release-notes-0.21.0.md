# Release Notes
- [Bug Fixes](#bug-fixes)
- [New Features](#new-features)
    - [Functional Enhancements](#functional-enhancements)
    - [RPC Additions](#rpc-additions)
    - [lncli Additions](#lncli-additions)
- [Improvements](#improvements)
    - [Functional Updates](#functional-updates)
    - [RPC Updates](#rpc-updates)
    - [lncli Updates](#lncli-updates)
    - [Breaking Changes](#breaking-changes)
    - [Performance Improvements](#performance-improvements)
    - [Deprecations](#deprecations)
- [Technical and Architectural Updates](#technical-and-architectural-updates)
    - [BOLT Spec Updates](#bolt-spec-updates)
    - [Testing](#testing)
    - [Database](#database)
    - [Code Health](#code-health)
    - [Tooling and Documentation](#tooling-and-documentation)
- [Contributors (Alphabetical Order)](#contributors)

# Bug Fixes

# New Features

- Basic Support for [onion messaging forwarding](https://github.com/lightningnetwork/lnd/pull/9868) 
  consisting of a new message type, `OnionMessage`. This includes the message's
  definition, comprising a path key and an onion blob, along with the necessary
  serialization and deserialization logic for peer-to-peer communication.

## Functional Enhancements

* To support scenarios where an external entity, such as a remote router, 
  manages the payment lifecycle via the Switch RPC server, the node must 
  preserve the history of HTLC attempts across restarts. This [behavior](https://github.com/lightningnetwork/lnd/pull/10178) is now 
  conditional on how the lnd binary is built. When compiled with the `switchrpc`
  build tag, the local `routing.ChannelRouter`'s automatic cleanup of the
  dispatcher's (Switch) attempt store on startup is disabled. This shifts the
  responsibility of state cleanup to the external controller, which is expected
  to use an RPC interface (e.g., switchrpc) to manage the lifecycle of attempts.
  Tying this behavior to a build tag, rather than a runtime flag, makes the
  binary's purpose explicit and prevents potential misconfigurations.

## RPC Additions

* Added a new [switchrpc RPC sub-system](https://github.com/lightningnetwork/lnd/pull/9489)
  with `SendOnion`, `BuildOnion`, and `TrackOnion` endpoints. This allows the
  daemon to offload path-finding, onion construction and payment life-cycle
  management to an external entity and instead accept onion payments for direct
  delivery to the network. The new gRPC server should be used with caution. It
  is currently only safe to allow a *single* entity (either the local router or
  *one* external router) to dispatch attempts via the Switch at any given time.
  Running multiple controllers concurrently will lead to undefined behavior and
  potential loss of funds. The compilation of the server is hidden behind the
  non-default `switchrpc` build tag.

* Add [`DisableRemoteRouter` rpc](https://github.com/lightningnetwork/lnd/pull/10178) to `switchrpc` which marks the database as no 
  longer being used by a remote router. This is useful for migrating from a 
  remote router setup back to the default embedded router. This RPC will fail if
  there are any active, in-flight HTLCs.

## lncli Additions

# Improvements
## Functional Updates

## RPC Updates

## lncli Updates

## Breaking Changes

## Performance Improvements

## Deprecations

# Technical and Architectural Updates
## BOLT Spec Updates

## Testing

## Database

## Code Health

## Tooling and Documentation

# Contributors (Alphabetical Order)
