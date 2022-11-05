# bobcats

Cross-platform cryptography (JVM, Node.js, browsers) for the Cats ecosystem.
To learn more about the concept please see [http4s/http4s#5044](https://github.com/http4s/http4s/issues/5044).

```scala
libraryDependencies += "net.bblfish.crypto" %% "bobcats" % "0.2-${hash}-SNAPSHOT" 
```

where hash is one of the hashes published in the sonatype [net.bblfish.crypto](https://oss.sonatype.org/content/repositories/snapshots/net/bblfish/crypto/) snapshot repo.

## Current state
                         
## Symmetric Keys

bobcats has an implementation for symmetric keys on all three platforms (Java, Browser JS and Node JS)
and implementation of asymetric keys for Java and Browser JS needed for "Signing HTTP Messages"
examples. 
It is being used by [httpSig](https://github.com/bblfish/httpSig).

## Asymmetric Keys

bobcats has an implementions for asymmetric keys on Java and BrowserJS. To get NodeJS working we would need to select an implementation of the JS Crypto API for Node, or write code specifically using the Node Crypto libraries.


## Todo

- clean up the API a lot, especially improve algorithm names
- add more tests
- add more cryptographic suites

# Howto

## Running browser tests locally

To test the browser JS you need to install [the Selenium drivers](https://www.selenium.dev/downloads/) for your Operating Systems and have the corresponding browsers installed too.
