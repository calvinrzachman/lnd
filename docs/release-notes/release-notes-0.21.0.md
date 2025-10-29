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
## Functional Enhancements

## RPC Additions

## lncli Additions

# Improvements
## Functional Updates

## RPC Updates

## lncli Updates

## Breaking Changes

* Added [duplicate safety to `switch.SendHTLC`](https://github.com/lightningnetwork/lnd/pull/10049). This method will no longer
  forward an onion with the same attempt ID twice without the result for a given
  ID having been cleaned from the network result store. This ensures "at most
  once" delivery and request processing of a given HTLC attempt, allowing a
  remote router or rpc client to safely retry htlc dispatch requests without
  creating duplicate attempts. This extends the more narrow duplicate safety
  already provided by the Switch’s `CircuitMap`.

* The `ChannelRouter` has been updated to robustly handle the new error contract
  from the idempotent `switch.SendHTLC` function. When faced with a persistent
  and ambiguous dispatch error, the router will now prioritize fund safety by
  halting the payment's life-cycle manager. This prevents a class of bugs where
  an ambiguous error could be misinterpreted, potentially leading to a duplicate
  payment. Final resolution of the ambiguous attempt is safely deferred to the
  router's attempt resumption logic on restart.


## Performance Improvements

## Deprecations

# Technical and Architectural Updates
## BOLT Spec Updates

## Testing

## Database

## Code Health

## Tooling and Documentation

# Contributors (Alphabetical Order)
