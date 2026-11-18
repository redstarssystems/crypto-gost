package org.rssys.gost.pkix.cert;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Формы GeneralName (RFC 5280 §4.2.1.6), для которых библиотека не умеет проверять
 * ограничения NameConstraints.
 *
 * <p>RFC 5280 §4.2.1.10 требует либо обработать ограничение, либо отклонить сертификат,
 * если в нём встречается имя той же формы. Поэтому форма отслеживается раздельно в
 * NameConstraints и в SAN: пересечение множеств означает невозможность проверки.</p>
 */
public enum UnsupportedGeneralNameForm {
    /** otherName [0] */
    OTHER_NAME,
    /** x400Address [3] */
    X400_ADDRESS,
    /** ediPartyName [5] */
    EDI_PARTY_NAME,
    /** registeredID [8] */
    REGISTERED_ID;

    /**
     * Неизменяемая копия набора форм.
     *
     * <p>Обёртка {@code unmodifiableSet} над исходным множеством осталась бы «окном» в него:
     * внешний код, изменивший исходное множество, разошёл бы содержимое с производными
     * флагами. Поэтому множество копируется.</p>
     */
    static Set<UnsupportedGeneralNameForm> immutableCopyOf(
            Collection<UnsupportedGeneralNameForm> forms) {
        EnumSet<UnsupportedGeneralNameForm> copy = EnumSet.noneOf(UnsupportedGeneralNameForm.class);
        copy.addAll(forms);
        return Collections.unmodifiableSet(copy);
    }
}
