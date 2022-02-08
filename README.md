# bobcats

Cross-platform cryptography (JVM, Node.js, browsers) for the Cats ecosystem.
To learn more about the concept please see [http4s/http4s#5044](https://github.com/http4s/http4s/issues/5044).

```scala
libraryDependencies += "net.bblfish.crypto" %% "bobcats" % "0.2-${hash}-SNAPSHOT" 
```

where hash is one of the hashes published in the sonatype [net.bblfish.crypto](https://oss.sonatype.org/content/repositories/snapshots/net/bblfish/crypto/) snapshot repo.

## Current state

bobcats has implementation for symmetric keys on all three platforms (Java, Browser JS and Node JS)
and implementation of asymetric keys for Java and Browser JS needed for "Signing HTTP Messages"
examples. 
It is being used by [httpSig](https://github.com/bblfish/httpSig).

## Todo

- clean up the API a lot, especially improve algorithm names
- add more tests
- add more cryptographic suites
