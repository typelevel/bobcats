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

sealed abstract class PaddingMode {
  private[bobcats] def toStringJava: String
  private[bobcats] def setAutoPaddingNodeJS: Boolean
}

object PaddingMode {
  case object None extends PaddingMode {
    private[bobcats] override def toStringJava: String = "NoPadding"
    private[bobcats] def setAutoPaddingNodeJS: Boolean = false
  }
  case object PKCS7 extends PaddingMode {
    // The JCA erroneously refers to PKCS#7 padding as PKCS#5
    private[bobcats] override def toStringJava: String = "PKCS5Padding"
    private[bobcats] def setAutoPaddingNodeJS: Boolean = true
  }
}
