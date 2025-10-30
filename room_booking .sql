-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Oct 25, 2025 at 06:59 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `room_booking`
--

-- --------------------------------------------------------

--
-- Table structure for table `bookings`
--

CREATE TABLE `bookings` (
  `booking_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `room_id` int(11) NOT NULL,
  `slot_id` int(11) NOT NULL,
  `booking_date` date NOT NULL,
  `status` enum('pending','approved','rejected','reserved','cancelled') DEFAULT 'pending',
  `approver_id` int(11) DEFAULT NULL,
  `purpose` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `rooms`
--

CREATE TABLE `rooms` (
  `room_id` int(11) NOT NULL,
  `room_name` varchar(50) NOT NULL,
  `status` enum('free','disabled') DEFAULT 'free'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `rooms`
--

INSERT INTO `rooms` (`room_id`, `room_name`, `status`) VALUES
(1, 'Room A101', 'free'),
(2, 'Room A102', 'free'),
(3, 'Room B201', 'free'),
(4, 'Room B202', 'free'),
(5, 'Room C101', 'free'),
(6, 'Room C102', 'free'),
(7, 'Room C103', 'free');

-- --------------------------------------------------------

--
-- Table structure for table `room_status_log`
--

CREATE TABLE `room_status_log` (
  `log_id` int(11) NOT NULL,
  `room_id` int(11) NOT NULL,
  `slot_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `status` enum('free','pending','reserved','disabled') DEFAULT 'free',
  `updated_by` int(11) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `room_status_log`
--

INSERT INTO `room_status_log` (`log_id`, `room_id`, `slot_id`, `date`, `status`, `updated_by`, `updated_at`) VALUES
(0, 1, 1, '2025-10-26', 'free', 0, '2025-10-10 17:00:00');

-- --------------------------------------------------------

--
-- Table structure for table `time_slots`
--

CREATE TABLE `time_slots` (
  `slot_id` int(11) NOT NULL,
  `start_time` time NOT NULL,
  `end_time` time NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `time_slots`
--

INSERT INTO `time_slots` (`slot_id`, `start_time`, `end_time`) VALUES
(1, '08:00:00', '10:00:00'),
(2, '10:00:00', '12:00:00'),
(3, '13:00:00', '15:00:00'),
(4, '15:00:00', '17:00:00');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `user_id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('student','staff','lecturer') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `name`, `username`, `password`, `role`) VALUES
(1, 'naay', 'staffnaay', '$2b$10$9todN9mqsn.Nma5X8w5W2.9cs12qL4m8Om5hHxhr93gUtebm2CU/a', 'staff'),
(2, 'pun', 'staffpun', '$2b$10$9todN9mqsn.Nma5X8w5W2.9cs12qL4m8Om5hHxhr93gUtebm2CU/a', 'staff'),
(3, 'jame', 'lecjame', '$2b$10$9todN9mqsn.Nma5X8w5W2.9cs12qL4m8Om5hHxhr93gUtebm2CU/a', 'lecturer'),
(4, 'jeeno', 'lecjeeno', '$2b$10$ax0G3h0ezpTZfaCvbdIGQ.bcghST.rcJa79QOn.lf9QLdvlO2MsL6', 'lecturer'),
(5, 'ben', 'stdben', '$2b$10$ax0G3h0ezpTZfaCvbdIGQ.bcghST.rcJa79QOn.lf9QLdvlO2MsL6', 'student'),
(6, 'boss', 'stdboss', '$2b$10$ax0G3h0ezpTZfaCvbdIGQ.bcghST.rcJa79QOn.lf9QLdvlO2MsL6', 'student');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `bookings`
--
ALTER TABLE `bookings`
  ADD PRIMARY KEY (`booking_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `room_id` (`room_id`),
  ADD KEY `slot_id` (`slot_id`);

--
-- Indexes for table `rooms`
--
ALTER TABLE `rooms`
  ADD PRIMARY KEY (`room_id`);

--
-- Indexes for table `time_slots`
--
ALTER TABLE `time_slots`
  ADD PRIMARY KEY (`slot_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `bookings`
--
ALTER TABLE `bookings`
  MODIFY `booking_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `rooms`
--
ALTER TABLE `rooms`
  MODIFY `room_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `time_slots`
--
ALTER TABLE `time_slots`
  MODIFY `slot_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `bookings`
--
ALTER TABLE `bookings`
  ADD CONSTRAINT `bookings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`),
  ADD CONSTRAINT `bookings_ibfk_2` FOREIGN KEY (`room_id`) REFERENCES `rooms` (`room_id`),
  ADD CONSTRAINT `bookings_ibfk_3` FOREIGN KEY (`slot_id`) REFERENCES `time_slots` (`slot_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
