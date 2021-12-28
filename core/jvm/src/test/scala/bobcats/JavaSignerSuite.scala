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

import bobcats.util.{BouncyJavaPEMUtils, PEMUtils}
import cats.effect.{MonadCancel, Sync, SyncIO}

import scala.util.Try

class JavaSignerSuite extends SignerSuite {

	override type IOX[+X] = SyncIO[X]

	override def extractPub(a: SyncIO[PublicKeySpec[PKA]]): Try[PublicKeySpec[PKA]] =
		Try(a.unsafeRunSync())
	override def extractPriv(a: SyncIO[PrivateKeySpec[PrivateKeyAlg]]): Try[PrivateKeySpec[PrivateKeyAlg]] =
		Try(a.unsafeRunSync())

	override def pemutils: PEMUtils[SyncIO] =
		BouncyJavaPEMUtils.forMonadError[SyncIO](cats.effect.SyncIO.syncForSyncIO)

	implicit val synio: Sync[SyncIO] with MonadCancel[SyncIO, Throwable] = SyncIO.syncForSyncIO
	implicit val signer: Signer[SyncIO] = Signer.forSync[SyncIO]
	implicit val verifier: Verifier[SyncIO] = Verifier.forSync[SyncIO]

	run(SigningHttpMessages.signatureExamples)
}