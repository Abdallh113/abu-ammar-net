package com.abuammar.net;

import com.getcapacitor.*;
import com.getcapacitor.annotation.CapacitorPlugin;
import org.json.*;
import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.*;

@CapacitorPlugin(name = "RouterOs")
public class RouterOsPlugin extends Plugin {

  static class Conn implements Closeable {
    Socket s; InputStream in; OutputStream out;
    Conn(String h, int p, int t) throws IOException {
      s = new Socket(); s.connect(new InetSocketAddress(h, p), t); s.setSoTimeout(t + 5000);
      in = new BufferedInputStream(s.getInputStream()); out = new BufferedOutputStream(s.getOutputStream());
    }
    public void close() { try { s.close(); } catch (Exception e) {} }
    void len(int l) throws IOException {
      if (l < 0x80) out.write(l);
      else if (l < 0x4000) { l |= 0x8000; out.write(l >> 8); out.write(l); }
      else if (l < 0x200000) { l |= 0xC00000; out.write(l >> 16); out.write(l >> 8); out.write(l); }
      else { out.write(0xE0 | (l >> 24)); out.write(l >> 16); out.write(l >> 8); out.write(l); }
    }
    void send(List<String> ws) throws IOException {
      for (String w : ws) { byte[] b = w.getBytes("UTF-8"); len(b.length); out.write(b); }
      out.write(0); out.flush();
    }
    int rb() throws IOException { int c = in.read(); if (c < 0) throw new IOException("closed"); return c; }
    int rlen() throws IOException {
      int c = rb();
      if (c < 0x80) return c;
      if (c < 0xC0) return ((c & 0x3F) << 8) | rb();
      if (c < 0xE0) { int a = rb(), b = rb(); return ((c & 0x1F) << 16) | (a << 8) | b; }
      if (c < 0xF0) { int a = rb(), b = rb(), d = rb(); return ((c & 0x0F) << 24) | (a << 16) | (b << 8) | d; }
      return (rb() << 24) | (rb() << 16) | (rb() << 8) | rb();
    }
    List<String> sentence() throws IOException {
      List<String> r = new ArrayList<>();
      while (true) {
        int l = rlen(); if (l == 0) return r;
        byte[] b = new byte[l]; int o = 0;
        while (o < l) { int n = in.read(b, o, l - o); if (n < 0) throw new IOException("closed"); o += n; }
        r.add(new String(b, "UTF-8"));
      }
    }
    JSONArray run(List<String> ws) throws Exception {
      send(ws);
      JSONArray arr = new JSONArray(); String err = null;
      while (true) {
        List<String> s = sentence(); if (s.isEmpty()) continue;
        String t = s.get(0);
        if (t.equals("!re") || t.equals("!done")) {
          JSONObject o = new JSONObject();
          for (int i = 1; i < s.size(); i++) {
            String w = s.get(i);
            if (w.startsWith("=")) { int k = w.indexOf('=', 1); if (k > 0) o.put(w.substring(1, k), w.substring(k + 1)); else o.put(w.substring(1), ""); }
          }
          if (t.equals("!re")) arr.put(o);
          else { if (err != null) throw new Exception("TRAP: " + err); if (o.length() > 0 && arr.length() == 0) arr.put(o); return arr; }
        } else if (t.equals("!trap")) {
          err = "error"; for (String w : s) if (w.startsWith("=message=")) err = w.substring(9);
        } else if (t.equals("!fatal")) throw new Exception("FATAL: " + (s.size() > 1 ? s.get(1) : ""));
      }
    }
    void login(String u, String p) throws Exception {
      JSONArray r = run(Arrays.asList("/login", "=name=" + u, "=password=" + p));
      if (r.length() > 0 && r.getJSONObject(0).has("ret")) {
        String ch = r.getJSONObject(0).getString("ret");
        byte[] c = new byte[ch.length() / 2];
        for (int i = 0; i < c.length; i++) c[i] = (byte) Integer.parseInt(ch.substring(2 * i, 2 * i + 2), 16);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update((byte) 0); md.update(p.getBytes("UTF-8")); md.update(c);
        StringBuilder sb = new StringBuilder("00");
        for (byte b : md.digest()) sb.append(String.format("%02x", b));
        run(Arrays.asList("/login", "=name=" + u, "=response=" + sb));
      }
    }
  }

  private Conn open(PluginCall c) throws Exception {
    Conn k = new Conn(c.getString("host"), c.getInt("port", 8728), 7000);
    try { k.login(c.getString("user", ""), c.getString("pass", "")); } catch (Exception e) { k.close(); throw e; }
    return k;
  }
  private List<String> words(String cmd, JSONObject a) {
    List<String> w = new ArrayList<>(); w.add(cmd);
    if (a != null) { Iterator<String> it = a.keys(); while (it.hasNext()) { String k = it.next(); w.add("=" + k + "=" + a.optString(k)); } }
    return w;
  }
  private static String msg(Exception e) {
    if (e instanceof SocketTimeoutException) return "TIMEOUT";
    if (e instanceof ConnectException) return "REFUSED";
    if (e instanceof UnknownHostException || e instanceof NoRouteToHostException) return "TIMEOUT";
    return e.getMessage() == null ? e.toString() : e.getMessage();
  }

  @PluginMethod
  public void exec(PluginCall c) {
    new Thread(() -> {
      try (Conn k = open(c)) {
        JSONArray r = k.run(words(c.getString("cmd"), new JSONObject(c.getString("attrs", "{}"))));
        JSObject o = new JSObject(); o.put("data", r.toString()); c.resolve(o);
      } catch (Exception e) { c.reject(msg(e)); }
    }).start();
  }

  @PluginMethod
  public void batch(PluginCall c) {
    new Thread(() -> {
      try (Conn k = open(c)) {
        JSONArray cmds = new JSONArray(c.getString("cmds", "[]"));
        int ok = 0, fail = 0; String first = "";
        for (int i = 0; i < cmds.length(); i++) {
          JSONObject x = cmds.getJSONObject(i);
          try { k.run(words(x.getString("cmd"), x.optJSONObject("attrs"))); ok++; }
          catch (Exception e) { fail++; if (first.isEmpty()) first = msg(e); if (e instanceof IOException) throw e; }
        }
        JSObject o = new JSObject(); o.put("ok", ok); o.put("fail", fail); o.put("error", first); c.resolve(o);
      } catch (Exception e) { c.reject(msg(e)); }
    }).start();
  }
}
