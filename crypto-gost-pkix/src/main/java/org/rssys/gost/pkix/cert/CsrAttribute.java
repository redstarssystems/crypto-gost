package org.rssys.gost.pkix.cert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Атрибут PKCS#10 CertificationRequest: OID и значения в сыром DER (RFC 2986 §4.1,
 * {@code Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }}).
 *
 * <p>Неизменяемый: массивы значений копируются на входе и на выходе. Это обычный класс,
 * а не {@code record}: у записи {@code equals} сравнивает массивы по ссылке.</p>
 *
 * <p><b>Секрет:</b> среди атрибутов может быть {@code challengePassword} в сыром виде. Значения
 * нужно обрабатывать как секрет. Новой утечки здесь нет (пароль и так лежит в
 * {@link GostCsrParser#getEncoded()}), но {@link #toString()} значений не выводит.</p>
 *
 * @see GostCsrParser#getAttributes()
 */
public final class CsrAttribute {

    private final String oid;
    private final byte[][] valuesDer;

    CsrAttribute(String oid, byte[][] valuesDer) {
        this.oid = Objects.requireNonNull(oid, "oid");
        // Инвариант неизменяемости держим локально, не полагаясь на единственного вызывающего
        this.valuesDer = new byte[valuesDer.length][];
        for (int i = 0; i < valuesDer.length; i++) {
            this.valuesDer[i] = valuesDer[i].clone();
        }
    }

    /** @return OID атрибута в точечной нотации */
    public String oid() {
        return oid;
    }

    /**
     * Возвращает значения атрибута: каждое — один целый DER-элемент (тег, длина, содержимое).
     * Порядок — как в CSR, то есть не обязательно отсортированный.
     *
     * <p>Может содержать секрет (см. описание класса). Копии затирает вызывающий.</p>
     *
     * @return новый список копий значений, не пустой
     */
    public List<byte[]> valuesDer() {
        List<byte[]> copy = new ArrayList<>(valuesDer.length);
        for (byte[] value : valuesDer) {
            copy.add(value.clone());
        }
        return Collections.unmodifiableList(copy);
    }

    /** Сравнивает OID и значения побайтно (в отличие от записи, не по ссылкам на массивы). */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CsrAttribute)) return false;
        CsrAttribute that = (CsrAttribute) o;
        return oid.equals(that.oid) && Arrays.deepEquals(valuesDer, that.valuesDer);
    }

    @Override
    public int hashCode() {
        return 31 * oid.hashCode() + Arrays.deepHashCode(valuesDer);
    }

    /** Значения в DER-кодировке не выводятся: среди них может быть секрет. */
    @Override
    public String toString() {
        return "CsrAttribute{oid=" + oid + ", values=" + valuesDer.length + "}";
    }
}
