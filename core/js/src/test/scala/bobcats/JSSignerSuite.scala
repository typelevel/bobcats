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

import bobcats.util.PEMUtils
import cats.effect.kernel.Async
import cats.effect.{IO, MonadCancel, Sync, SyncIO}

import scala.util.Try

class JSSignerSuite extends SignerSuite {
	override implicit def pemutils: PEMUtils[IO] =
		bobcats.util.WebCryptoPEMUtils.forASyncIO[IO](cats.effect.Async[IO])

	override type IOX[+X] = IO[X]

	override def extractPub(a: IO[PublicKeySpec[PKA]]): Try[PublicKeySpec[PKA]] =
		a.unsafeToFuture().value.get

	override def extractPriv(a: IO[PrivateKeySpec[PrivateKeyAlg]]): Try[PrivateKeySpec[PrivateKeyAlg]] =
		a.unsafeToFuture().value.get

	implicit val synio: Async[IO] = IO.asyncForIO

	implicit val signer: Signer[IO] = Signer.forAsync[IO]
	implicit val verifier: Verifier[IO] = Verifier.forAsync[IO]

	run[IO](SigningHttpMessages.signatureExamples)

}