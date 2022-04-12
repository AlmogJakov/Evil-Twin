# Protection-of-wireless-and-mobile-networks


--------------------------------------------------------------------------------------------------
פרטים על ההתקנה:
https://www.aircrack-ng.org/doku.php?id=install_aircrack    
מריצים את הפקודות תחת Compiling and installing (רץ חלק אם יש את כל הדרישות)
    
פקודות להתקנת הדרישות (אם צריך):    
אפשר להריץ לפני: sudo apt-get update -y (מעדכן מידע על חבילות)    
sudo apt-get install libz-dev    
sudo apt-get install libssl-dev    
sudo apt-get install ethtool    

--------------------------------------------------------------------------------------------------    

בדיקה אם התוכנה אכן קיימת: aircrack-ng    
(כמובן שאם צריך הרשאות אז מוסיפים sudo בתחילת הפקודה)

--------------------------------------------------------------------------------------------------    
בדיקת הזרקה: https://www.aircrack-ng.org/doku.php?id=injection_test    

* מידע על האיטרפייסים של הכרטיסים המחוברים: sudo /usr/local/sbin/airmon-ng    
  במידה ולא נמצא ניתן לחפש את הנתיב כך: find / -name airmon-ng   
* הפעלת בדיקה על איטרפייס ספציפי והגדרה מחדש: sudo airmon-ng start wlan0    
* בדיקת הזרקה: sudo aireplay-ng -9 wlan0mon     
* בדיקת סוגי התקפות (צריך 2 כרטיסים): sudo aireplay-ng -9 -i wlan1mon wlan0mon   
 (כאשר הכרטיס wlan0mon הוא התוקף) 

(בפקודות השם של האיטרפייס הוא wlan0mon/wlan0 אבל מפעילים את הפקודה על השם של האיטרפייס שמצאנו אצלנו)

--------------------------------------------------------------------------------------------------    
קישורי מידע נוספים:     
https://shushan.co.il/%D7%94%D7%AA%D7%A7%D7%A4%D7%AA-wi-fi-%D7%94%D7%A6%D7%A4%D7%A0%D7%94-%D7%9E%D7%A1%D7%95%D7%92-wep-%D7%95%D7%91%D7%99%D7%A6%D7%95%D7%A2-packet-injecting
