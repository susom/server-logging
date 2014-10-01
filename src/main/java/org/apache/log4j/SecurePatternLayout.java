/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.log4j;

import org.apache.log4j.helpers.PatternConverter;
import org.apache.log4j.helpers.PatternParser;
import org.apache.log4j.spi.LoggingEvent;


// Contributors:   Nelson Minar <nelson@monkey.org>
//                 Anders Kristensen <akristensen@dynamicsoft.com>

/**
   This is a modified version of the default PatternLayout that attempts to
   prevent malicious injection of content into the log by appending a marker
   (\u00D9 by default - ASCII code 174) to the end of each log message. That
   marker will be escaped (by \u00AA by default - ASCII code 170) if the message
   contains it. Occurrences of the escape character will be replaced by two escape
   characters. The stack trace will always be included inside the log message,
   and the message will always be followed by the platform specific newline after
   the record separator. If the pattern specifies a newline (%n) at the end of the
   message that will be ignored. The remainder of this class, documentation, and
   behavior remains the same.

   ----- Original documentation:

   A flexible layout configurable with pattern string.
   
   This code is known to have synchronization and other issues
   which are not present in org.apache.log4j.EnhancedPatternLayout.
   EnhancedPatternLayout should be used in preference to PatternLayout.
   EnhancedPatternLayout is distributed in the log4j extras companion.

   <p>The goal of this class is to {@link #format format} a {@link
   org.apache.log4j.spi.LoggingEvent} and return the results as a String. The results
   depend on the <em>conversion pattern</em>.

   <p>The conversion pattern is closely related to the conversion
   pattern of the printf function in C. A conversion pattern is
   composed of literal text and format control expressions called
   <em>conversion specifiers</em>.

   <p><i>You are free to insert any literal text within the conversion
   pattern.</i>

   <p>Each conversion specifier starts with a percent sign (%) and is
   followed by optional <em>format modifiers</em> and a <em>conversion
   character</em>. The conversion character specifies the type of
   data, e.g. category, priority, date, thread name. The format
   modifiers control such things as field width, padding, left and
   right justification. The following is a simple example.

   <p>Let the conversion pattern be <b>"%-5p [%t]: %m%n"</b> and assume
   that the log4j environment was set to use a PatternLayout. Then the
   statements
   <pre>
   Category root = Category.getRoot();
   root.debug("Message 1");
   root.warn("Message 2");
   </pre>
   would yield the output
   <pre>
   DEBUG [main]: Message 1
   WARN  [main]: Message 2
   </pre>

   <p>Note that there is no explicit separator between text and
   conversion specifiers. The pattern parser knows when it has reached
   the end of a conversion specifier when it reads a conversion
   character. In the example above the conversion specifier
   <b>%-5p</b> means the priority of the logging event should be left
   justified to a width of five characters.

   The recognized conversion characters are

   <p>
   <table border="1" CELLPADDING="8">
   <th>Conversion Character</th>
   <th>Effect</th>

   <tr>
     <td align=center><b>c</b></td>

     <td>Used to output the category of the logging event. The
     category conversion specifier can be optionally followed by
     <em>precision specifier</em>, that is a decimal constant in
     brackets.

     <p>If a precision specifier is given, then only the corresponding
     number of right most components of the category name will be
     printed. By default the category name is printed in full.

     <p>For example, for the category name "a.b.c" the pattern
     <b>%c{2}</b> will output "b.c".

     </td>
   </tr>

   <tr>
     <td align=center><b>C</b></td>

     <td>Used to output the fully qualified class name of the caller
     issuing the logging request. This conversion specifier
     can be optionally followed by <em>precision specifier</em>, that
     is a decimal constant in brackets.

     <p>If a precision specifier is given, then only the corresponding
     number of right most components of the class name will be
     printed. By default the class name is output in fully qualified form.

     <p>For example, for the class name "org.apache.xyz.SomeClass", the
     pattern <b>%C{1}</b> will output "SomeClass".

     <p><b>WARNING</b> Generating the caller class information is
     slow. Thus, use should be avoided unless execution speed is
     not an issue.

     </td>
     </tr>

   <tr> <td align=center><b>d</b></td> <td>Used to output the date of
	 the logging event. The date conversion specifier may be
	 followed by a <em>date format specifier</em> enclosed between
	 braces. For example, <b>%d{HH:mm:ss,SSS}</b> or
	 <b>%d{dd&nbsp;MMM&nbsp;yyyy&nbsp;HH:mm:ss,SSS}</b>.  If no
	 date format specifier is given then ISO8601 format is
	 assumed.

	 <p>The date format specifier admits the same syntax as the
	 time pattern string of the {@link
	 java.text.SimpleDateFormat}. Although part of the standard
	 JDK, the performance of <code>SimpleDateFormat</code> is
	 quite poor.

	 <p>For better results it is recommended to use the log4j date
	 formatters. These can be specified using one of the strings
	 "ABSOLUTE", "DATE" and "ISO8601" for specifying {@link
	 org.apache.log4j.helpers.AbsoluteTimeDateFormat
	 AbsoluteTimeDateFormat}, {@link
	 org.apache.log4j.helpers.DateTimeDateFormat DateTimeDateFormat}
	 and respectively {@link
	 org.apache.log4j.helpers.ISO8601DateFormat
	 ISO8601DateFormat}. For example, <b>%d{ISO8601}</b> or
	 <b>%d{ABSOLUTE}</b>.

	 <p>These dedicated date formatters perform significantly
	 better than {@link java.text.SimpleDateFormat}.
     </td>
   </tr>

   <tr>
   <td align=center><b>F</b></td>

   <td>Used to output the file name where the logging request was
   issued.

   <p><b>WARNING</b> Generating caller location information is
   extremely slow and should be avoided unless execution speed
   is not an issue.

   </tr>

   <tr>
   <td align=center><b>l</b></td>

     <td>Used to output location information of the caller which generated
     the logging event.

     <p>The location information depends on the JVM implementation but
     usually consists of the fully qualified name of the calling
     method followed by the callers source the file name and line
     number between parentheses.

     <p>The location information can be very useful. However, its
     generation is <em>extremely</em> slow and should be avoided
     unless execution speed is not an issue.

     </td>
   </tr>

   <tr>
   <td align=center><b>L</b></td>

   <td>Used to output the line number from where the logging request
   was issued.

   <p><b>WARNING</b> Generating caller location information is
   extremely slow and should be avoided unless execution speed
   is not an issue.

   </tr>


   <tr>
     <td align=center><b>m</b></td>
     <td>Used to output the application supplied message associated with
     the logging event.</td>
   </tr>

   <tr>
   <td align=center><b>M</b></td>

   <td>Used to output the method name where the logging request was
   issued.

   <p><b>WARNING</b> Generating caller location information is
   extremely slow and should be avoided unless execution speed
   is not an issue.

   </tr>

   <tr>
     <td align=center><b>n</b></td>

     <td>Outputs the platform dependent line separator character or
     characters.

     <p>This conversion character offers practically the same
     performance as using non-portable line separator strings such as
     "\n", or "\r\n". Thus, it is the preferred way of specifying a
     line separator.


   </tr>

   <tr>
     <td align=center><b>p</b></td>
     <td>Used to output the priority of the logging event.</td>
   </tr>

   <tr>

     <td align=center><b>r</b></td>

     <td>Used to output the number of milliseconds elapsed from the construction
     of the layout until the creation of the logging event.</td>
   </tr>


   <tr>
     <td align=center><b>t</b></td>

     <td>Used to output the name of the thread that generated the
     logging event.</td>

   </tr>

   <tr>

     <td align=center><b>x</b></td>

     <td>Used to output the NDC (nested diagnostic context) associated
     with the thread that generated the logging event.
     </td>
   </tr>


   <tr>
     <td align=center><b>X</b></td>

     <td>

     <p>Used to output the MDC (mapped diagnostic context) associated
     with the thread that generated the logging event. The <b>X</b>
     conversion character <em>must</em> be followed by the key for the
     map placed between braces, as in <b>%X{clientNumber}</b> where
     <code>clientNumber</code> is the key. The value in the MDC
     corresponding to the key will be output.</p>

     <p>See {@link org.apache.log4j.MDC} class for more details.
     </p>

     </td>
   </tr>

   <tr>

     <td align=center><b>%</b></td>

     <td>The sequence %% outputs a single percent sign.
     </td>
   </tr>

   </table>

   <p>By default the relevant information is output as is. However,
   with the aid of format modifiers it is possible to change the
   minimum field width, the maximum field width and justification.

   <p>The optional format modifier is placed between the percent sign
   and the conversion character.

   <p>The first optional format modifier is the <em>left justification
   flag</em> which is just the minus (-) character. Then comes the
   optional <em>minimum field width</em> modifier. This is a decimal
   constant that represents the minimum number of characters to
   output. If the data item requires fewer characters, it is padded on
   either the left or the right until the minimum width is
   reached. The default is to pad on the left (right justify) but you
   can specify right padding with the left justification flag. The
   padding character is space. If the data item is larger than the
   minimum field width, the field is expanded to accommodate the
   data. The value is never truncated.

   <p>This behavior can be changed using the <em>maximum field
   width</em> modifier which is designated by a period followed by a
   decimal constant. If the data item is longer than the maximum
   field, then the extra characters are removed from the
   <em>beginning</em> of the data item and not from the end. For
   example, it the maximum field width is eight and the data item is
   ten characters long, then the first two characters of the data item
   are dropped. This behavior deviates from the printf function in C
   where truncation is done from the end.

   <p>Below are various format modifier examples for the category
   conversion specifier.

   <p>
   <TABLE BORDER=1 CELLPADDING=8>
   <th>Format modifier
   <th>left justify
   <th>minimum width
   <th>maximum width
   <th>comment

   <tr>
   <td align=center>%20c</td>
   <td align=center>false</td>
   <td align=center>20</td>
   <td align=center>none</td>

   <td>Left pad with spaces if the category name is less than 20
   characters long.

   <tr> <td align=center>%-20c</td> <td align=center>true</td> <td
   align=center>20</td> <td align=center>none</td> <td>Right pad with
   spaces if the category name is less than 20 characters long.

   <tr>
   <td align=center>%.30c</td>
   <td align=center>NA</td>
   <td align=center>none</td>
   <td align=center>30</td>

   <td>Truncate from the beginning if the category name is longer than 30
   characters.

   <tr>
   <td align=center>%20.30c</td>
   <td align=center>false</td>
   <td align=center>20</td>
   <td align=center>30</td>

   <td>Left pad with spaces if the category name is shorter than 20
   characters. However, if category name is longer than 30 characters,
   then truncate from the beginning.

   <tr>
   <td align=center>%-20.30c</td>
   <td align=center>true</td>
   <td align=center>20</td>
   <td align=center>30</td>

   <td>Right pad with spaces if the category name is shorter than 20
   characters. However, if category name is longer than 30 characters,
   then truncate from the beginning.

   </table>

   <p>Below are some examples of conversion patterns.

   <dl>

   <p><dt><b>%r [%t] %-5p %c %x - %m%n</b>
   <p><dd>This is essentially the TTCC layout.

   <p><dt><b>%-6r [%15.15t] %-5p %30.30c %x - %m%n</b>

   <p><dd>Similar to the TTCC layout except that the relative time is
   right padded if less than 6 digits, thread name is right padded if
   less than 15 characters and truncated if longer and the category
   name is left padded if shorter than 30 characters and truncated if
   longer.

  </dl>

   <p>The above text is largely inspired from Peter A. Darnell and
   Philip E. Margolis' highly recommended book "C -- a Software
   Engineering Approach", ISBN 0-387-97389-3.

   @author <a href="mailto:cakalijp@Maritz.com">James P. Cakalic</a>
   @author Ceki G&uuml;lc&uuml;


   @since 0.8.2 */
public class SecurePatternLayout extends Layout {
  /**
   * Default character to use to mark boundaries between log messages.
   */
  private static final String DEFAULT_RECORD_SEPARATOR = "\u00AE";
  /**
   * Default character to use to escape occurrences of the record separator
   * withing messages. If this escape character occurs it will be duplicated
   * (one escape character is replaced with two escape characters).
   */
  private static final String DEFAULT_ESCAPE_CHARACTER = DEFAULT_RECORD_SEPARATOR;


  /** Default pattern string for log output. Currently set to the
      string <b>"%m%n"</b> which just prints the application supplied
      message. */
  public final static String DEFAULT_CONVERSION_PATTERN ="%m%n";

  /** A conversion pattern equivalent to the TTCCCLayout.
      Current value is <b>%r [%t] %p %c %x - %m%n</b>. */
  public final static String TTCC_CONVERSION_PATTERN
                                             = "%r [%t] %p %c %x - %m%n";


  protected final int BUF_SIZE = 256;
  protected final int MAX_CAPACITY = 1024;


  // output buffer appended to when format() is invoked
  private StringBuffer sbuf = new StringBuffer(BUF_SIZE);

  private String pattern;

  private PatternConverter head;

  private String recordSeparator = DEFAULT_RECORD_SEPARATOR;

  private String escapeCharacter = DEFAULT_ESCAPE_CHARACTER;

  /**
     Constructs a PatternLayout using the DEFAULT_LAYOUT_PATTERN.

     The default pattern just produces the application supplied message.
  */
  public SecurePatternLayout() {
    this(DEFAULT_CONVERSION_PATTERN);
  }

  /**
     Constructs a PatternLayout using the supplied conversion pattern.
  */
  public SecurePatternLayout(String pattern) {
    this.pattern = pattern;
    head = createPatternParser((pattern == null) ? DEFAULT_CONVERSION_PATTERN :
			     pattern).parse();
  }

   /**
     Set the <b>ConversionPattern</b> option. This is the string which
     controls formatting and consists of a mix of literal content and
     conversion specifiers.
   */
  public
  void setConversionPattern(String conversionPattern) {
    pattern = conversionPattern;
    head = createPatternParser(conversionPattern).parse();
  }

  /**
     Returns the value of the <b>ConversionPattern</b> option.
   */
  public
  String getConversionPattern() {
    return pattern;
  }

  /**
   * Set the <b>RecordSeparator</b> option. This is a string which indicates
   * the boundary between log messages. If any part of a log message contains
   * this string it will be escaped using the {@link #setEscapeCharacter(String)}.
   * The default value is {@link #DEFAULT_RECORD_SEPARATOR}.
   */
  public void setRecordSeparator(String recordSeparator) {
    this.recordSeparator = recordSeparator;
  }

  public String getRecordSeparator() {
    return recordSeparator;
  }

  /**
   * Set the <b>EscapeCharacter</b> option. This is a string which will be used
   * to escape occurrences of the {@link #setRecordSeparator(String)} within the
   * log message. Occurrences of this character within the log message will be
   * replaces by a sequence of two of these characters. The default value is
   * {@link #DEFAULT_ESCAPE_CHARACTER}, which is the same as the default record
   * separator. If the record separator and escape character are the same, then
   * occurrences within the message will be escaped only once.
   */
  public void setEscapeCharacter(String escapeCharacter) {
    this.escapeCharacter = escapeCharacter;
  }

  public String getEscapeCharacter() {
    return escapeCharacter;
  }

  /**
     Does not do anything as options become effective
  */
  public
  void activateOptions() {
    // nothing to do.
  }

  /**
   * This modified version does handle the throwable so it will be included inside
   * the escaped content, so this method now returns <code>false</code>.
   *
   * @since 0.8.4
   */
  public
  boolean ignoresThrowable() {
    return false;
  }

  /**
    Returns PatternParser used to parse the conversion string. Subclasses
    may override this to return a subclass of PatternParser which recognize
    custom conversion characters.

    @since 0.9.0
  */
  protected PatternParser createPatternParser(String pattern) {
    return new PatternParser(pattern);
  }

  /**
     Produces a formatted string as specified by the conversion pattern.
  */
  public String format(LoggingEvent event) {
    // Reset working stringbuffer
    if(sbuf.capacity() > MAX_CAPACITY) {
      sbuf = new StringBuffer(BUF_SIZE);
    } else {
      sbuf.setLength(0);
    }

    PatternConverter c = head;

    while(c != null) {
      c.format(sbuf, event);
      c = c.next;
    }

    // Include the throwable, if any, so it will be properly escaped and wrapped
    String[] s = event.getThrowableStrRep();
    if (s != null) {
      int len = s.length;
      for(int i = 0; i < len; i++) {
        sbuf.append(s[i]);
        sbuf.append(Layout.LINE_SEP);
      }
    }

    // Escape any occurences of the escape character in the content
    int offset = 0;
    int nextOccurence;
    while ((nextOccurence = sbuf.indexOf(escapeCharacter, offset)) != -1) {
      sbuf.insert(nextOccurence, escapeCharacter);
      offset = nextOccurence + 2;
    }
    // Escape any occurences of the record separator in the content
    if (!recordSeparator.equals(escapeCharacter)) {
      offset = 0;
      while ((nextOccurence = sbuf.indexOf(recordSeparator, offset)) != -1) {
        sbuf.insert(nextOccurence, escapeCharacter);
        offset = nextOccurence + 2;
      }
    }
    // Add the end mark, adjusting the line separator, if any
    if (sbuf.lastIndexOf(Layout.LINE_SEP) == sbuf.length() - Layout.LINE_SEP_LEN) {
      sbuf.insert(sbuf.length() - Layout.LINE_SEP_LEN, recordSeparator);
    } else {
      sbuf.append(recordSeparator);
      sbuf.append(Layout.LINE_SEP);
    }

    return sbuf.toString();
  }
}
