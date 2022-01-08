libraryDependencies += "org.scala-js" %% "scalajs-env-selenium" % "1.1.1"

resolvers += Resolver.sonatypeRepo("snapshots")
addSbtPlugin("org.typelevel" % "sbt-typelevel" % "0.4-f8f808f-SNAPSHOT")
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.8.0")
addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.10.0")
