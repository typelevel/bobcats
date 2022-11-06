/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bobcats

/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import bobcats.util.{PEMUtils, WebCryptoPEMUtils}
import cats.effect.IO
import cats.effect.kernel.{Async, Sync}

class JSSignerSuite07 extends SignerSuite {
  override implicit val pemutils: PEMUtils = WebCryptoPEMUtils

  implicit val synio: Async[IO] = IO.asyncForIO

  implicit val signer: Signer[IO] = Signer.forAsync[IO]
  implicit val verifier: Verifier[IO] = Verifier.forAsync[IO]
  implicit val s: Sync[IO] = Async[IO]

  if (!BuildInfo.runtime.contains("NodeJS")) {
    // this could be perhaps done with `munit.Tag`s . Also it would be nice to
    // have this be in a warning color.
    val okForWebCryptAPI = HttpMessageSignaturesV07.sigExamples.groupBy { sigEx =>
      sigEx.notFor().collectFirst { case _: NoWebCryptAPI => false }.getOrElse(true)
    }
    for (sigEx <- okForWebCryptAPI(false)) {
      test(s"cannot run test ${sigEx.description} because of ${sigEx.notFor()}") {}
    }
    run[IO](okForWebCryptAPI(true))
  }
  // we have not implemented crypto for NodeJS yet

}

class JSSignerSuite13 extends SignerSuite {
  override implicit val pemutils: PEMUtils = WebCryptoPEMUtils

  implicit val synio: Async[IO] = IO.asyncForIO

  implicit val signer: Signer[IO] = Signer.forAsync[IO]
  implicit val verifier: Verifier[IO] = Verifier.forAsync[IO]
  implicit val hmac: Hmac[IO] = Hmac.forAsyncOrSync[IO]
  implicit val s: Sync[IO] = Async[IO]

  if (!BuildInfo.runtime.contains("NodeJS")) {
    // this could be perhaps done with `munit.Tag`s . Also it would be nice to
    // have this be in a warning color.
    val okForWebCryptAPI = HttpMessageSignaturesV07.sigExamples.groupBy { sigEx =>
      sigEx.notFor().collectFirst { case _: NoWebCryptAPI => false }.getOrElse(true)
    }
    for (sigEx <- okForWebCryptAPI(false)) {
      test(s"cannot run test ${sigEx.description} because of ${sigEx.notFor()}") {}
    }
    run[IO](okForWebCryptAPI(true))
    runSym[IO](HttpMessageSignaturesV13.symSignExamples)
  }
  // we have not implemented crypto for NodeJS yet
}
