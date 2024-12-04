 // Timer logic to show countdown
 var timer = 120;  // 2 minutes in seconds
 var countdown = setInterval(function() {
     var minutes = Math.floor(timer / 60);
     var seconds = timer % 60;
     document.getElementById('timer').textContent = 
       (minutes < 10 ? '0' : '') + minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
     
     if (timer <= 0) {
         clearInterval(countdown);
         // Store OTP expiry message
         sessionStorage.setItem('otpExpiredMessage', 'Your OTP has expired. Please try again.');
         // Redirect to login page
         window.location.href = '/'; // Replace '/login' with your actual login page URL
     }
     timer--;
 }, 1000);