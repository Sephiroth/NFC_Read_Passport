   M S B A M L   `   `   `  ����T  PDigitalCredentialsCabinet, Version=1.0.0.0, Culture=neutral, PublicKeyToken=nullE'clr-namespace:DigitalCredentialsCabinetDigitalCredentialsCabinet  5   	   *    $DigitalCredentialsCabinet.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   9local'clr-namespace:DigitalCredentialsCabinet     5   	   -   5          �Name$  
mainWindow��5   	    � Title$ 欢迎登陆��5   	   $	��350��6   $	��525��6#   .��5	      � .+�5
   
   �� -   5         ��Name$ textBox_number��5
      $
��Left=�6*   $��15��6E   $��	80,65,0,0q�6Q    �� TextWrapping$
 Wrap=�6d   $��	E41604138��6x   $	��Top=�6�   $	��105��6�   �� 5   
   -   5        $ textBox_birth��5      $
��Left=�6)   $��15��6D   $��	80,90,0,0q�6P   $
 Wrap=�6c   $��890415��6w   $	��Top=�6�   $	��105��6�   �� 5   
   -   5        $ textBox_expiry��5      $
��Left=�6*   $��15��6E   $��
80,115,0,0q�6Q   $
 Wrap=�6e   $��250108��6y   $	��Top=�6�   $	��105��6�   �� 5   
   -   5         ��Name$ button_export��5      $��生成keySeed��6(   $
��Left=�6<   $��
85,151,0,0q�6W   $	��Top=�6k   $��75��6�   6�   �� 5   
   -   5         ��Name$ label��5      $��	证件号��6   $
��Left=�6-   $��	15,61,0,0q�6H   $	��Top=�6[   $��24��6s   $��45��6   �� 5   
   -   5        $ 
label_Copy��5      $��生日��6$   $
��Left=�61   $��	15,85,0,0q�6L   $	��Top=�6_   $��24��6w   $��45��6�   �� 5   
   -   5        $ label_Copy1��5      $��有效日期��6%   $
��Left=�64   $��
15,109,0,0q�6O   $	��Top=�6c   $��24��6{   $��60��6�   �� 5   
   -	   5        $ label1��5      $��	随机数��6    $
��Left=�6.   $��
220,80,0,0q�6I   $	��Top=�6]   $��55��6u   �� 5   
   -
   5        $ textBox_getChallenge��5      $
��Left=�60   $��15��6K   $��
275,85,0,0q�6W   $
 Wrap=�6k   $	��Top=�6   $	��165��6�   �� 5   
   -   5        $ textBox1��5      $
��Left=�6$   $	��145��6?   $��235,140,0,0q�6L   $
 Wrap=�6a   $��TextBox��6u   $	��Top=�6�   $	��245��6�   5      5      