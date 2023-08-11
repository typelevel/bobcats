scalacOptions += "-Ypartial-unification"
libraryDependencies ++= Seq(
  "org.typelevel" %% "cats-parse" % "0.3.8",
  "org.scodec" %% "scodec-bits" % "1.1.34",
  "org.scalameta" %% "scalameta" % "4.5.11",
)
