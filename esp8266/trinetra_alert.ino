/*
  ============================================================
                    TRINETRA SOC
                 ESP8266 ALERT DEVICE
  ============================================================

  Project:
      TRINETRA SOC

  Purpose:
      Physical security alert device for the TRINETRA SOC SIEM.

  Communication:
      USB Serial
      Baud Rate: 115200

  Wiring:
      D1 / GPIO5  -> Buzzer
      D5 / GPIO14 -> LED
      GND         -> GND

  Supported Commands:

      CRITICAL
      HIGH
      STOP
      TEST
      STATUS
      PING

  Alert Behavior:

      CRITICAL:
          10 sec ON
          3 sec OFF
          10 sec ON
          3 sec OFF
          Repeat
          Maximum duration: 60 seconds

      HIGH:
          1 sec ON
          1 sec OFF
          Maximum duration: 10 seconds

  ============================================================
*/

#define BUZZER_PIN D1
#define LED_PIN    D5

#define SERIAL_BAUD 115200

#define CRITICAL_DURATION 60000UL
#define HIGH_DURATION     10000UL

// ------------------------------------------------------------
// Alert states
// ------------------------------------------------------------

enum AlertState {

  ALERT_IDLE,
  ALERT_HIGH,
  ALERT_CRITICAL

};

AlertState alertState = ALERT_IDLE;


// ------------------------------------------------------------
// Timing
// ------------------------------------------------------------

unsigned long alertStartTime = 0;


// ------------------------------------------------------------
// Serial command buffer
// ------------------------------------------------------------

String commandBuffer = "";


// ============================================================
// SET OUTPUTS
// ============================================================

void outputsOn() {

  digitalWrite(
    BUZZER_PIN,
    HIGH
  );

  digitalWrite(
    LED_PIN,
    HIGH
  );

}


void outputsOff() {

  digitalWrite(
    BUZZER_PIN,
    LOW
  );

  digitalWrite(
    LED_PIN,
    LOW
  );

}


// ============================================================
// STOP ALERT
// ============================================================

void stopAlert() {

  alertState = ALERT_IDLE;

  alertStartTime = 0;

  outputsOff();

  Serial.println(
    "ALERT STOPPED"
  );

}


// ============================================================
// START HIGH ALERT
// ============================================================

void startHighAlert() {

  alertState = ALERT_HIGH;

  alertStartTime = millis();

  outputsOff();

  Serial.println(
    "HIGH ALERT STARTED"
  );

}


// ============================================================
// START CRITICAL ALERT
// ============================================================

void startCriticalAlert() {

  alertState = ALERT_CRITICAL;

  alertStartTime = millis();

  outputsOff();

  Serial.println(
    "CRITICAL ALERT STARTED"
  );

}


// ============================================================
// TEST ALERT
// ============================================================

void testAlert() {

  Serial.println(
    "TEST ALERT STARTED"
  );

  // ----------------------------------------------------------
  // 1 second ON
  // ----------------------------------------------------------

  outputsOn();

  delay(1000);

  // ----------------------------------------------------------
  // OFF
  // ----------------------------------------------------------

  outputsOff();

  Serial.println(
    "TEST ALERT COMPLETE"
  );

}


// ============================================================
// STATUS
// ============================================================

void sendStatus() {

  if (
    alertState
    ==
    ALERT_CRITICAL
  ) {

    Serial.println(
      "STATUS: CRITICAL"
    );

  }

  else if (
    alertState
    ==
    ALERT_HIGH
  ) {

    Serial.println(
      "STATUS: HIGH"
    );

  }

  else {

    Serial.println(
      "STATUS: IDLE"
    );

  }

}


// ============================================================
// COMMAND HANDLER
// ============================================================

void handleCommand(
  String command
) {

  command.trim();

  command.toUpperCase();


  // ----------------------------------------------------------
  // CRITICAL
  // ----------------------------------------------------------

  if (
    command
    ==
    "CRITICAL"
  ) {

    startCriticalAlert();

  }


  // ----------------------------------------------------------
  // HIGH
  // ----------------------------------------------------------

  else if (
    command
    ==
    "HIGH"
  ) {

    startHighAlert();

  }


  // ----------------------------------------------------------
  // STOP
  // ----------------------------------------------------------

  else if (
    command
    ==
    "STOP"
  ) {

    stopAlert();

  }


  // ----------------------------------------------------------
  // TEST
  // ----------------------------------------------------------

  else if (
    command
    ==
    "TEST"
  ) {

    testAlert();

  }


  // ----------------------------------------------------------
  // STATUS
  // ----------------------------------------------------------

  else if (
    command
    ==
    "STATUS"
  ) {

    sendStatus();

  }


  // ----------------------------------------------------------
  // PING
  // ----------------------------------------------------------

  else if (
    command
    ==
    "PING"
  ) {

    Serial.println(
      "PONG"
    );

  }


  // ----------------------------------------------------------
  // Unknown command
  // ----------------------------------------------------------

  else {

    Serial.print(
      "UNKNOWN COMMAND: "
    );

    Serial.println(
      command
    );

  }

}


// ============================================================
// SERIAL INPUT
// ============================================================

void readSerialCommands() {

  while (
    Serial.available()
    >
    0
  ) {

    char incomingChar =
      Serial.read();


    // --------------------------------------------------------
    // End of command
    // --------------------------------------------------------

    if (
      incomingChar
      ==
      '\n'
      ||
      incomingChar
      ==
      '\r'
    ) {

      if (
        commandBuffer.length()
        >
        0
      ) {

        handleCommand(
          commandBuffer
        );

        commandBuffer = "";

      }

    }


    // --------------------------------------------------------
    // Normal character
    // --------------------------------------------------------

    else {

      commandBuffer +=
        incomingChar;


      // ------------------------------------------------------
      // Prevent unlimited buffer growth
      // ------------------------------------------------------

      if (
        commandBuffer.length()
        >
        50
      ) {

        commandBuffer = "";

      }

    }

  }

}


// ============================================================
// UPDATE HIGH ALERT
// ============================================================

void updateHighAlert() {

  unsigned long elapsed =
    millis()
    -
    alertStartTime;


  // ----------------------------------------------------------
  // Automatically stop after 10 seconds
  // ----------------------------------------------------------

  if (
    elapsed
    >=
    HIGH_DURATION
  ) {

    stopAlert();

    return;

  }


  // ----------------------------------------------------------
  // 1 second ON / 1 second OFF
  // ----------------------------------------------------------

  unsigned long cycle =
    elapsed
    %
    2000UL;


  if (
    cycle
    <
    1000UL
  ) {

    outputsOn();

  }

  else {

    outputsOff();

  }

}


// ============================================================
// UPDATE CRITICAL ALERT
// ============================================================

void updateCriticalAlert() {

  unsigned long elapsed =
    millis()
    -
    alertStartTime;


  // ----------------------------------------------------------
  // Automatically stop after 60 seconds
  // ----------------------------------------------------------

  if (
    elapsed
    >=
    CRITICAL_DURATION
  ) {

    stopAlert();

    return;

  }


  /*
      Critical pattern:

      10 seconds ON
       3 seconds OFF
      10 seconds ON
       3 seconds OFF

      Total cycle = 26 seconds

      Repeats until 60 seconds.
  */


  unsigned long cycle =
    elapsed
    %
    26000UL;


  // ----------------------------------------------------------
  // First ON period
  // ----------------------------------------------------------

  if (
    cycle
    <
    10000UL
  ) {

    outputsOn();

  }


  // ----------------------------------------------------------
  // First OFF period
  // ----------------------------------------------------------

  else if (
    cycle
    <
    13000UL
  ) {

    outputsOff();

  }


  // ----------------------------------------------------------
  // Second ON period
  // ----------------------------------------------------------

  else if (
    cycle
    <
    23000UL
  ) {

    outputsOn();

  }


  // ----------------------------------------------------------
  // Second OFF period
  // ----------------------------------------------------------

  else {

    outputsOff();

  }

}


// ============================================================
// UPDATE ALERT
// ============================================================

void updateAlert() {

  if (
    alertState
    ==
    ALERT_HIGH
  ) {

    updateHighAlert();

  }

  else if (
    alertState
    ==
    ALERT_CRITICAL
  ) {

    updateCriticalAlert();

  }

}


// ============================================================
// SETUP
// ============================================================

void setup() {

  // ----------------------------------------------------------
  // Configure pins
  // ----------------------------------------------------------

  pinMode(
    BUZZER_PIN,
    OUTPUT
  );

  pinMode(
    LED_PIN,
    OUTPUT
  );


  // ----------------------------------------------------------
  // Make sure outputs start OFF
  // ----------------------------------------------------------

  outputsOff();


  // ----------------------------------------------------------
  // Start Serial
  // ----------------------------------------------------------

  Serial.begin(
    SERIAL_BAUD
  );


  // ----------------------------------------------------------
  // ESP8266 startup delay
  // ----------------------------------------------------------

  delay(1000);


  // ----------------------------------------------------------
  // Startup message
  // ----------------------------------------------------------

  Serial.println();

  Serial.println(
    "================================"
  );

  Serial.println(
    "       TRINETRA SOC"
  );

  Serial.println(
    "    ESP8266 ALERT DEVICE"
  );

  Serial.println(
    "================================"
  );

  Serial.println(
    "STATUS: READY"
  );

  Serial.println(
    "BAUD: 115200"
  );

  Serial.println(
    "BUZZER: D1 / GPIO5"
  );

  Serial.println(
    "LED: D5 / GPIO14"
  );

  Serial.println(
    "================================"
  );

  Serial.println();

}


// ============================================================
// MAIN LOOP
// ============================================================

void loop() {

  // ----------------------------------------------------------
  // Read commands from TRINETRA SIEM
  // ----------------------------------------------------------

  readSerialCommands();


  // ----------------------------------------------------------
  // Update current alert
  // ----------------------------------------------------------

  updateAlert();

}