using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

// vault file: salt(16) | iv(16) | aes-256-cbc ciphertext | hmac-sha256(32) over everything before it
// keys: pbkdf2-sha256 of the master password -> 32 bytes for aes + 32 bytes for hmac
public class Vault
{
    const int Iterations = 200000;
    readonly string file;
    byte[] salt, encKey, macKey;
    public List<string[]> Items = new List<string[]>();

    public Vault(string file) { this.file = file; }

    public bool Exists { get { return File.Exists(file); } }

    // creates the vault if missing. returns false on wrong password or tampered file
    public bool Open(string password)
    {
        byte[] data = Exists ? File.ReadAllBytes(file) : null;
        salt = data != null ? Slice(data, 0, 16) : RandomBytes(16);
        byte[] k;
        using (var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256)) k = kdf.GetBytes(64);
        encKey = Slice(k, 0, 32);
        macKey = Slice(k, 32, 32);
        Items.Clear();
        if (data == null) { Save(); return true; }
        int n = data.Length - 32;
        if (n < 48 || !SameBytes(Mac(data, n), Slice(data, n, 32))) return false;
        byte[] plain;
        using (var aes = Aes.Create())
        using (var dec = aes.CreateDecryptor(encKey, Slice(data, 16, 16)))
            plain = dec.TransformFinalBlock(data, 32, n - 32);
        foreach (string line in Encoding.UTF8.GetString(plain).Split('\n'))
            if (line.Length > 0) Items.Add(line.Split('\t'));
        return true;
    }

    public void Close() { Items.Clear(); encKey = macKey = null; }

    public void Save()
    {
        var sb = new StringBuilder();
        foreach (string[] e in Items) sb.Append(string.Join("\t", e)).Append('\n');
        byte[] plain = Encoding.UTF8.GetBytes(sb.ToString());
        byte[] iv = RandomBytes(16), cipher;
        using (var aes = Aes.Create())
        using (var enc = aes.CreateEncryptor(encKey, iv))
            cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
        var ms = new MemoryStream();
        ms.Write(salt, 0, 16);
        ms.Write(iv, 0, 16);
        ms.Write(cipher, 0, cipher.Length);
        byte[] body = ms.ToArray();
        ms.Write(Mac(body, body.Length), 0, 32);
        // write a temp file first so a crash mid-write never eats the vault
        Directory.CreateDirectory(Path.GetDirectoryName(file));
        string tmp = file + ".tmp";
        File.WriteAllBytes(tmp, ms.ToArray());
        if (Exists) File.Replace(tmp, file, null); else File.Move(tmp, file);
    }

    public static string Generate(int length)
    {
        const string chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?";
        var sb = new StringBuilder();
        while (sb.Length < length)
            foreach (byte b in RandomBytes(length))
                // drop bytes past the last full multiple so every char is equally likely
                if (b < 256 - 256 % chars.Length && sb.Length < length) sb.Append(chars[b % chars.Length]);
        return sb.ToString();
    }

    byte[] Mac(byte[] data, int count) { using (var h = new HMACSHA256(macKey)) return h.ComputeHash(data, 0, count); }

    static bool SameBytes(byte[] a, byte[] b)
    {
        int d = a.Length ^ b.Length;
        for (int i = 0; i < a.Length && i < b.Length; i++) d |= a[i] ^ b[i];
        return d == 0;
    }

    static byte[] Slice(byte[] a, int start, int len) { var r = new byte[len]; Buffer.BlockCopy(a, start, r, 0, len); return r; }

    static byte[] RandomBytes(int n) { var r = new byte[n]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(r); return r; }
}

// the window is just an old ie webbrowser control showing plain html.
// buttons on the page call the public Do* methods through window.external
[ComVisible(true)]
public class App : Form
{
    readonly WebBrowser web = new WebBrowser();
    readonly Vault vault = new Vault(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "podot", "vault.dat"));
    readonly Timer clipTimer = new Timer { Interval = 30000 };
    bool unlocked;
    string copied, msg = "";

    public App()
    {
        Text = "podot";
        ClientSize = new System.Drawing.Size(640, 480);
        web.Dock = DockStyle.Fill;
        web.ObjectForScripting = this;
        web.IsWebBrowserContextMenuEnabled = false;
        web.AllowWebBrowserDrop = false;
        web.ScriptErrorsSuppressed = true;
        // only our own generated page, never navigate anywhere else
        web.Navigating += (s, e) => { if (e.Url.ToString() != "about:blank") e.Cancel = true; };
        Controls.Add(web);
        clipTimer.Tick += (s, e) =>
        {
            clipTimer.Stop();
            if (Clipboard.ContainsText() && Clipboard.GetText() == copied) Clipboard.Clear();
        };
        Render();
    }

    public void DoCreate(string pw, string again)
    {
        if (pw == "") msg = "password cannot be empty";
        else if (pw != again) msg = "passwords do not match";
        else unlocked = vault.Open(pw);
        Later();
    }

    public void DoUnlock(string pw)
    {
        unlocked = vault.Open(pw);
        if (!unlocked) { vault.Close(); msg = "wrong password"; }
        Later();
    }

    public void DoLock() { unlocked = false; vault.Close(); Later(); }

    public void DoAdd(string site, string user, string pass)
    {
        if (site.Trim() == "" || pass == "") msg = "site and password are required";
        else { vault.Items.Add(new[] { Clean(site), Clean(user), Clean(pass) }); Persist(); }
        Later();
    }

    public void DoDelete(int i) { vault.Items.RemoveAt(i); Persist(); Later(); }

    public void DoCopy(int i)
    {
        copied = vault.Items[i][2];
        var d = new DataObject();
        d.SetText(copied);
        // keep it out of win+v clipboard history and cloud clipboard
        d.SetData("CanIncludeInClipboardHistory", new MemoryStream(new byte[4]));
        d.SetData("CanUploadToCloudClipboard", new MemoryStream(new byte[4]));
        Clipboard.SetDataObject(d, true);
        clipTimer.Stop();
        clipTimer.Start();
        msg = "password copied. clipboard clears in 30 seconds.";
        Later();
    }

    public string DoGenerate() { return Vault.Generate(20); }

    void Persist()
    {
        try { vault.Save(); }
        catch (Exception ex) { msg = "could not save: " + ex.Message.ToLower(); }
    }

    // re-render after the script call returns, not inside it
    void Later() { BeginInvoke((MethodInvoker)Render); }

    static string Clean(string s) { return s.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' '); }

    static string Enc(string s) { return WebUtility.HtmlEncode(s); }

    void Render()
    {
        var h = new StringBuilder();
        h.Append("<html><head><style>body,td,th{font:12px verdana,arial}body{margin:12px;background:#fff}th{background:#ddd;text-align:left}</style></head>");
        h.Append("<body onload=\"var f=document.getElementById('f');if(f)f.focus()\"><h2>podot</h2>");
        if (msg != "") h.Append("<p><font color=red>" + Enc(msg) + "</font></p>");
        msg = "";
        if (!vault.Exists)
        {
            h.Append("<p>no vault yet. pick a master password. if you forget it, everything is gone.</p>");
            h.Append("<form onsubmit=\"window.external.DoCreate(f.value,c.value);return false\"><table>");
            h.Append("<tr><td>master password</td><td><input type=password id=f></td></tr>");
            h.Append("<tr><td>again</td><td><input type=password id=c></td></tr>");
            h.Append("</table><input type=submit value=\"create vault\"></form>");
        }
        else if (!unlocked)
        {
            h.Append("<form onsubmit=\"window.external.DoUnlock(f.value);return false\">");
            h.Append("master password <input type=password id=f> <input type=submit value=unlock></form>");
        }
        else
        {
            h.Append("<p><button type=button onclick=\"window.external.DoLock()\">lock</button></p>");
            h.Append("<table border=1 cellpadding=4 cellspacing=0 width=100%><tr><th>site</th><th>user</th><th>password</th><th></th></tr>");
            for (int i = 0; i < vault.Items.Count; i++)
            {
                string[] e = vault.Items[i];
                h.Append("<tr><td>" + Enc(e[0]) + "</td><td>" + Enc(e[1]) + "&nbsp;</td><td>********</td><td nowrap>");
                h.Append("<button type=button onclick=\"window.external.DoCopy(" + i + ")\">copy</button> ");
                h.Append("<button type=button onclick=\"if(confirm('delete this entry?'))window.external.DoDelete(" + i + ")\">delete</button></td></tr>");
            }
            if (vault.Items.Count == 0) h.Append("<tr><td colspan=4><i>nothing here yet</i></td></tr>");
            h.Append("</table><hr><b>add entry</b>");
            h.Append("<form onsubmit=\"window.external.DoAdd(s.value,u.value,p.value);return false\"><table>");
            h.Append("<tr><td>site</td><td><input id=s size=30></td></tr>");
            h.Append("<tr><td>user</td><td><input id=u size=30></td></tr>");
            h.Append("<tr><td>password</td><td><input id=p size=30> <button type=button onclick=\"p.value=window.external.DoGenerate()\">generate</button></td></tr>");
            h.Append("</table><input type=submit value=add></form>");
        }
        h.Append("</body></html>");
        web.DocumentText = h.ToString();
    }

    // run with --selftest: exit code 0 means crypto round trip, wrong password and tamper checks pass
    static bool SelfTest()
    {
        string f = Path.Combine(Path.GetTempPath(), "podot-selftest.dat");
        File.Delete(f);
        var v = new Vault(f);
        v.Open("right");
        v.Items.Add(new[] { "site", "me", "héllo" });
        v.Save();
        bool ok = !new Vault(f).Open("wrong");
        var w = new Vault(f);
        ok = ok && w.Open("right") && w.Items.Count == 1 && w.Items[0][2] == "héllo";
        byte[] b = File.ReadAllBytes(f);
        b[40] ^= 1;
        File.WriteAllBytes(f, b);
        ok = ok && !new Vault(f).Open("right");
        ok = ok && Vault.Generate(20).Length == 20;
        File.Delete(f);
        return ok;
    }

    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--selftest") Environment.Exit(SelfTest() ? 0 : 1);
        Application.EnableVisualStyles();
        Application.Run(new App());
    }
}
