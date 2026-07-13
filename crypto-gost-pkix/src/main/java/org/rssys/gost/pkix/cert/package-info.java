/**
 * PKIX-объекты и их валидация по ГОСТ.
 *
 * <h2>Принцип выбора типа возврата методов верификации</h2>
 *
 * <table>
 *   <caption>boolean vs throws PkixException</caption>
 *   <tr><th>Тип возврата</th><th>Критерий</th><th>Примеры</th></tr>
 *   <tr>
 *     <td>{@code boolean}</td>
 *     <td>Проверка ровно одного факта (криптографическая подпись, hostname, IP-адрес, срок действия)</td>
 *     <td>{@link GostCertificate#verifySignature}, {@link GostCertificate#verifyHostname},
 *         {@link GostCertificate#isExpired}, {@link GostCsrParser#verify}</td>
 *   </tr>
 *   <tr>
 *     <td>{@code void throws PkixException}</td>
 *     <td>Проверка с хотя бы одним precondition-чеком (статус ответа, запрос подписан?)
 *         или многошаговая протокольная валидация (CRL: дата, подпись, структура)</td>
 *     <td>{@link GostOcspRequest#verifySignature}, {@link GostOcspResponse#verify},
 *         {@link GostCrl#verify}, {@link CrlVerifier#verify},
 *         {@link OcspVerifier#verify}, {@link ChainValidator#validateChain}</td>
 *   </tr>
 * </table>
 *
 * <p>Все методы, возвращающие {@code boolean}, чей результат критичен для безопасности
 * (проверка подписи, срока действия, hostname), аннотированы {@link CheckReturnValue} —
 * статический анализатор предупредит, если возврат не проверен. Сюда включены
 * и property-геттеры вроде {@code isExpired()} — риск «забыл проверить» для них
 * не ниже, чем для явных {@code verify*()} вызовов.</p>
 *
 * <p>Эта развилка осознанная: {@code boolean} отражает однозначный ответ на один вопрос
 * (как {@code java.security.Signature.verify()}), а {@link PkixException} с типизированным
 * {@link PkixException.Reason} даёт вызывающему коду полную диагностику для разных причин
 * провала многошаговой проверки.</p>
 *
 * @see PkixException
 * @see CheckReturnValue
 */
package org.rssys.gost.pkix.cert;

import org.rssys.gost.pkix.CheckReturnValue;
