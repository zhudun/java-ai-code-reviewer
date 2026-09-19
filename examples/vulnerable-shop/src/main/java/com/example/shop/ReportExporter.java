package com.example.shop;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;

public class ReportExporter {

    public String readReport(String path) throws Exception {
        InputStream in = new FileInputStream(path);
        BufferedReader reader = new BufferedReader(new FileReader(path));
        return reader.readLine();
    }

    public String safeRead(String path) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        }
    }
}
