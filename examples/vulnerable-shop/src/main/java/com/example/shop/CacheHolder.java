package com.example.shop;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CacheHolder {
    private static CacheHolder instance;
    private static final SimpleDateFormat FORMAT = new SimpleDateFormat("yyyy-MM-dd");

    public static CacheHolder getInstance() {
        if (instance == null) {
            synchronized (CacheHolder.class) {
                if (instance == null) {
                    instance = new CacheHolder();
                }
            }
        }
        return instance;
    }

    public String today() {
        return FORMAT.format(new Date());
    }
}
