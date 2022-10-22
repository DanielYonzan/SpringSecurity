package com.daniel.springsecurity.student;

import lombok.Data;
import lombok.Getter;
import lombok.ToString;

/**
 * @author Daniel Tamang
 * @since 9/29/2022
 */
@Data
@ToString
public class Student {

    private final Integer studentId;
    private final String studentName;
}
