libraryDependencies += "org.scala-js" %% "scalajs-env-selenium" % "1.1.1"

resolvers ++= Resolver.sonatypeOssRepos("snapshots")
addSbtPlugin("org.typelevel" % "sbt-typelevel" % "0.5.0-M5")
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.11.0")
addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.11.0")
