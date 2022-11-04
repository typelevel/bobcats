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

import bobcats.HttpMessageSignaturesV07.`Github-Issue-1509-Example`
import bobcats.util.{PEMUtils, WebCryptoPEMUtils}
import cats.effect.IO
import cats.effect.kernel.Async

class JSSignerSuite07 extends SignerSuite {
  override implicit val pemutils: PEMUtils = WebCryptoPEMUtils

  implicit val synio: Async[IO] = IO.asyncForIO

  implicit val signer: Signer[IO] = Signer.forAsync[IO]
  implicit val verifier: Verifier[IO] = Verifier.forAsync[IO]

  if (!BuildInfo.runtime.contains("NodeJS")) {
    run[IO](HttpMessageSignaturesV07.sigExamples.filterNot(_ == `Github-Issue-1509-Example`))
  }
  // we have not implemented crypto for NodeJS yet
    
}

class JSSignerSuite13 extends SignerSuite {
  override implicit val pemutils: PEMUtils = WebCryptoPEMUtils

  implicit val synio: Async[IO] = IO.asyncForIO

  implicit val signer: Signer[IO] = Signer.forAsync[IO]
  implicit val verifier: Verifier[IO] = Verifier.forAsync[IO]

  if (!BuildInfo.runtime.contains("NodeJS")) {
    run[IO](HttpMessageSignaturesV13.sigExamples.filterNot(_ == `Github-Issue-1509-Example`))
//    runSym[IO](HttpMessageSignaturesV13.symSignExamples)
  }
  // we have not implemented crypto for NodeJS yet
}
