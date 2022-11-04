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

class JavaSignerSuite07 extends SignerSuite {

  override def pemutils: PEMUtils = BouncyJavaPEMUtils

  implicit val synio: Sync[SyncIO] with MonadCancel[SyncIO, Throwable] = SyncIO.syncForSyncIO
  implicit val signer: Signer[SyncIO] = Signer.forSync[SyncIO]
  implicit val verifier: Verifier[SyncIO] = Verifier.forSync[SyncIO]

  run[SyncIO](HttpMessageSignaturesV07.sigExamples)
}

class JavaSignerSuiteV13 extends SignerSuite {

  override def pemutils: PEMUtils = BouncyJavaPEMUtils

  implicit val synio: Sync[SyncIO] with MonadCancel[SyncIO, Throwable] = SyncIO.syncForSyncIO
  implicit val signer: Signer[SyncIO] = Signer.forSync[SyncIO]
  implicit val verifier: Verifier[SyncIO] = Verifier.forSync[SyncIO]

  run[SyncIO](HttpMessageSignaturesV13.sigExamples)
  runSym[SyncIO](HttpMessageSignaturesV13.symSignExamples)
}
