package lbj;

public class Abc {
    public static void main(String[] args) throws Exception {
        String siyao = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIDidhhazfFRUTltW0Yln2P5hiQ1YrTluEjmXLfyT+B5BKhDSzeUFmL6vaX4x4WDcKfvN75dp5pZayHn8D3dBJjAON5n4u1yOH8UWsAfgoaNPkgNbCTGoo7/kjpVwhbUx3vfSaj2cQRWRAOerE5D6kSfC6Kk5M4u7FWbWi2DeExHAgMBAAECgYA0bGi+tUipTHsuUaXbnXf8sUT3u2M/02Sm+lRiWcRVuMPFMUIKBEkqz3SOaue1Dean2CyjWPLQXGiwLOhSMXEpoEmAZTsGqy42J3l2kWs33fCunlVfzrZWp60C2GUZ//pKzq3QUwlSii5GovmlM9VdQUC5dDMuNolAqosiWWeLkQJBAMYzV7fVOMOLmWsZ+JxRRLHd9Dfn2gU6XCmTPSRiTNE5KkK9PONgpzRa4BqFYofEUTsrGXx9tOI7GjvipUA87TkCQQCmeFa7Ac7cA7qEBiZRtS1ysWxrN0VPOtZ6pqRASfTkhjcsZKKJiS3+Zhdk6zbbv3OyQsqzyon18v6fjYjuAIV/AkBEFP7ctvF4uktI7vLnP0NJleR+D7ZkdVeTMHCgPuQEOo65vidcM6c75Lt2YLsnx9ffaz6l9Mhdrc+lIoWBO2yBAkBr6IHAAzIGKFyVDC92s4zcVepDrbY935P8OV0rV0VphR7qpek+Yi/wQllTz6zl0Tq8CNPAq7+2MGehIWvra2cdAkA1DBfrSUukjMgy6HXFkEYuIX1coz9u4vXvYDFvEKC11/wU7emqikRl4szn5yNhFwmr2RQT6xwVXrQbd68/lZIG";
        String gongyao = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCA4nYYWs3xUVE5bVtGJZ9j+YYkNWK05bhI5ly38k/geQSoQ0s3lBZi+r2l+MeFg3Cn7ze+XaeaWWsh5/A93QSYwDjeZ+Ltcjh/FFrAH4KGjT5IDWwkxqKO/5I6VcIW1Md730mo9nEEVkQDnqxOQ+pEnwuipOTOLuxVm1otg3hMRwIDAQAB";

        String aa = RSAUtils.sign("liangbo".getBytes(), siyao);
        System.out.println(aa);

        boolean as = RSAUtils.verify("liangbo".getBytes(), gongyao, aa);
        System.out.println(as);
    }
}
