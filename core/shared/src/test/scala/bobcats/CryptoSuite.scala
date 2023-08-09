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

import cats.effect.{IO, Resource}
import munit.CatsEffectSuite

trait CryptoSuite extends CatsEffectSuite {

  private val cryptoFixture = ResourceSuiteLocalFixture(
    "crypto",
    // TODO: If we want to pool, which would be quite nice. This _ought_ to return a resouce
    Resource.make(Crypto.forAsync[IO])(_ => IO.unit)
  )

  override def munitFixtures = List(cryptoFixture)

  implicit def crypto: Crypto[IO] = cryptoFixture()
  implicit def hash: Hash[IO] = crypto.hash

}

