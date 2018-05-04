using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace DigitalCredentialsCabinet
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void button_export_Click(object sender, RoutedEventArgs e)
        {
            string num = textBox_number.Text;
            string birthday = textBox_birth.Text;
            string expiry = textBox_expiry.Text;
            if (num.Equals("") || birthday.Equals("") || expiry.Equals(""))
            {
                MessageBox.Show("输入信息不能为空");
                return;
            }

            /*byte[] keySeed = MyUtil.EncryptUtil.computekeyseed(num, birthday, expiry, true);
            string cache = "";
            for (int i=0;i<keySeed.Length;i++)
            {
                cache += Convert.ToString(keySeed[i], 16) + ",";
            }
            MessageBox.Show(cache);*/

            string randomNum = textBox_getChallenge.Text.Trim();
            string[] cnStr = randomNum.Split(' ');

            if (cnStr.Length != 8)
            {
                MessageBox.Show("随机数长度错误!");
                return;
            }
            byte[] getCn = new byte[8];
            for (int i=0;i<8;i++)
            {
                getCn[i] = Convert.ToByte(cnStr[i], 16);
            }
            
            byte[] ss = MyUtil.EncryptUtil.doBAC(num, birthday, expiry, getCn);
            if (ss.Length <1)
            {
                MessageBox.Show("error");
                return;
            }
            StringBuilder sb = new StringBuilder("");
            string cache = null;
            for (int i=0;i<ss.Length;i++)
            {
                cache = null;
                cache = Convert.ToString(ss[i], 16).ToUpper();
                //if (cache.Length == 1)
                //{
                //    cache += "0" + cache;
                //}
                sb.Append(cache).Append(" ");
            }
            textBox1.Text = sb.ToString();

        }
    }
}
