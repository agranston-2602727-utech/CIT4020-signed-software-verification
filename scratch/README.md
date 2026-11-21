# scratch/

Throwaway working area for test copies and the second (attacker / unknown)
publisher used in T7 and T10. Everything in here except this README is ignored
by Git and must never go into the source ZIP.

Typical contents during testing:

```
scratch/release_T3/          copy of release_A for T3
scratch/release_T7/          copy signed by the second publisher
scratch/other_keys/          second publisher's private key (T7)
scratch/other_verifier/      second publisher's registry (T7)
```

Reset at any time with `rm -rf scratch/release_T* scratch/other_*`.
