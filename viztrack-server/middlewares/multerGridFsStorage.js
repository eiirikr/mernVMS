const multer = require('multer');
const { GridFsStorage } = require('multer-gridfs-storage');

const gridFsStorage=()=>{
  let StorageFs = new GridFsStorage({
  url: process.env.MONGODB_URI,
  file: (req, file) => {
    console.log(file.originalname);
    return {
      bucketName: 'employee_profiles',
      filename: file.originalname,
      collection: 'employee_details' 
    }
  }
});

let uploadGrid = multer({storage:StorageFs});
return uploadGrid;

}

module.exports = gridFsStorage;