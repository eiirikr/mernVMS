import React,{ createContext, useContext, useState } from 'react';
import blankProfile from "../src/blank-profile-picture.jpg"

// create a context
const FormContext = createContext();

// create a provider component to store and manage the form data
export const FormProvider = ({ children }) => {

   const initialVisitorFormData = {
        firstName: '',
        lastName: '',
        gender: '',
        age: '',
        designation: '',
        mobileNo: '',
        email: '',
        address: '',
  };

  const initialEmpFormData = {
        name: '',
        gender: '',
        age: '',
        designation: '',
        department:'',
        mobileNo: '',
        email: '',
        address: '',
        appliedLeave:'',
        leaveStatus:'Choose Status',
        leaveStart:'',
        leaveEnd:'',
        onsite:'',
        onsiteStart:'',
        onsiteEnd:''
  };

  const initialMeetingFormData = {
        autofillVisitorInput:'',
        autofillEmpInput:'',
        visitorID: '',
        visitorName: '',
        visitorDesignation: '',
        visitorMobileNo: '',
        visitorAddress:'',
        employeeID: '',
        employeeName: '',
        employeeDesignation: '',
        employeeDepartment: '',
        employeeEmail: '',
        employeeMobileNo: '',
        meetingDuration: '',
        meetingPurpose:''
  };

  const initialPreregisterFormData = {
        autofillVisitorInput:'',
        autofillEmpInput:'',
        visitorID: '',
        visitorName: '',
        visitorDesignation: '',
        visitorMobileNo: '',
        visitorAddress:'',
        employeeID: '',
        employeeName: '',
        employeeDesignation: '',
        employeeDepartment: '',
        employeeEmail: '',
        employeeMobileNo: '',
        meetingDate:'',
        meetingStartTime: '',
        meetingEndTime: '',
        meetingPurpose:''
  };

  const [visitorFormData, setVisitorFormData] = useState(initialVisitorFormData);
  const [empFormData, setEmpFormData] = useState(initialEmpFormData);
  const[profileImg, setProfileImg]= useState('');
  const[profileImgUrl, setProfileImgUrl]= useState(blankProfile);
  const [meetingFormData, setMeetingFormData] = useState(initialMeetingFormData);
  const [preregisterFormData, setPreregisterFormData] = useState(initialPreregisterFormData);

  return (
    <FormContext.Provider value={{ 
        visitorFormData, setVisitorFormData, initialVisitorFormData,
        empFormData, setEmpFormData, initialEmpFormData, profileImg, setProfileImg, profileImgUrl, setProfileImgUrl,
        meetingFormData, setMeetingFormData, initialMeetingFormData,
        preregisterFormData, setPreregisterFormData, initialPreregisterFormData 
    }}>
      {children}
    </FormContext.Provider>
  );
};

// create a custom hook to easily access the context
export const useFormContext = () => useContext(FormContext);