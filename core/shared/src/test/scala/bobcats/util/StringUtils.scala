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

package bobcats.util

import java.util.Base64
import scala.annotation.tailrec

object StringUtils {
  val singleSlsh = raw"\\\n *".r

  implicit class StringW(val str: String) extends AnyVal {

    /**
     * following [[https://tools.ietf.org/html/rfc8792#section-7.2.2 RFC8792 §7.2.2]] single
     * slash line unfolding algorithm
     */
    def rfc8792single: String = singleSlsh.replaceAllIn(str.stripMargin, "")

    def base64Decode: Array[Byte] = Base64.getDecoder.decode(str)

    def toRfc8792single(leftPad: Int = 4, maxLineLength: Int = 79): String = {
      @tailrec
      def lengthSplit(
          remaining: String,
          buf: List[String] = List(),
          firstLine: Boolean = true): List[String] = {
        if (remaining.isEmpty) buf.reverse
        else {
          val n = if (firstLine) maxLineLength else maxLineLength - leftPad
          val (headStr, remainingStr) = remaining.splitAt(n)
          lengthSplit(remainingStr, headStr :: buf, false)
        }
      }

      str
        .split("\\R")
        .toList
        .map { line => lengthSplit(line).mkString("\\\n" + (" " * leftPad)) }
        .mkString("\n")
    }
  }

}
