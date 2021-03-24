package pl.adrian.springsecurity.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Adrian P"),
            new Student(2, "Anna Smith"),
            new Student(3, "Hubert F")
    );

    // hasRole, hasAnyRole, hasAuthority, hasAnyAuthority

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PreAuthorize("hasAuthority('student:write')")
    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @PreAuthorize("hasAuthority('student:write')")
    @DeleteMapping("/{studentId}")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println(studentId);
    }

    @PreAuthorize("hasAuthority('student:write')")
    @PutMapping("/{studentId}")
    public void updateStudent(@PathVariable Integer studentId, @RequestBody Student student) {
        System.out.println(studentId + ", " + student);
    }
}
