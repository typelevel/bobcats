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

package bobcats.facade.node

import scala.scalajs.js

// https://nodejs.org/api/crypto.html
@js.native
private[bobcats] trait crypto extends js.Any {

  def getHashes(): js.Array[String] = js.native

  def createHash(algorithm: String): Hash = js.native

  def createHmac(algorithm: String, key: js.typedarray.Uint8Array): Hmac = js.native

  def createSecretKey(key: js.typedarray.Uint8Array): SymmetricKeyObject = js.native

  def generateKey(
      `type`: String,
      options: GenerateKeyOptions,
      callback: js.Function2[js.Error, SymmetricKeyObject, Unit]): Unit = js.native

  def generateKeySync(`type`: String, options: GenerateKeyOptions): SymmetricKeyObject =
    js.native

  def randomBytes(size: Int): js.typedarray.Uint8Array = js.native

  def randomBytes(
      size: Int,
      callback: js.UndefOr[js.Function2[js.Error, js.typedarray.Uint8Array, Unit]]): Unit =
    js.native

  def timingSafeEqual(
      a: js.typedarray.Uint8Array,
      b: js.typedarray.Uint8Array
  ): Boolean = js.native

}

@js.native
private[bobcats] trait GenerateKeyOptions extends js.Any
private[bobcats] object GenerateKeyOptions {
  def apply(length: Int): GenerateKeyOptions =
    js.Dynamic.literal(length = length).asInstanceOf[GenerateKeyOptions]
}
