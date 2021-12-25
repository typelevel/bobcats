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

///*
// * Copyright 2021 Typelevel
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *     http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
package bobcats

import bobcats.util.{PEMUtils, WebCryptoPEMUtils}
import cats.effect.IO
import munit.CatsEffectSuite

class JSSignerSuite extends CatsEffectSuite {

	implicit def PU: PEMUtils[IO] =
		WebCryptoPEMUtils.forASyncIO[IO]

	test("can I parse a PEM?") {
//		assertIO(IO(4),4)
		assertIO(
			PU.getPrivateKeyFromPEM(SigningHttpMessages.`test-key-rsa-pss`.privateKey).map(pk=>
			  pk.algorithm
			),
			PKA.RSA.Private
		)
	}

}
